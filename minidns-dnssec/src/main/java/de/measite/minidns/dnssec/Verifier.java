/*
 * Copyright 2015-2016 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.dnssec;

import de.measite.minidns.DNSName;
import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.dnssec.UnverifiedReason.AlgorithmExceptionThrownReason;
import de.measite.minidns.dnssec.UnverifiedReason.AlgorithmNotSupportedReason;
import de.measite.minidns.dnssec.UnverifiedReason.NSECDoesNotMatchReason;
import de.measite.minidns.dnssec.algorithms.AlgorithmMap;
import de.measite.minidns.record.DNSKEY;
import de.measite.minidns.record.DS;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.NSEC;
import de.measite.minidns.record.NSEC3;
import de.measite.minidns.record.RRSIG;
import de.measite.minidns.util.Base32;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

class Verifier {
    private AlgorithmMap algorithmMap = AlgorithmMap.INSTANCE;

    public UnverifiedReason verify(Record<DNSKEY> dnskeyRecord, DS ds) {
        DNSKEY dnskey = dnskeyRecord.payloadData;
        DigestCalculator digestCalculator = algorithmMap.getDsDigestCalculator(ds.digestType);
        if (digestCalculator == null) {
            return new AlgorithmNotSupportedReason(ds.digestTypeByte, "DS", dnskeyRecord);
        }

        byte[] dnskeyData = dnskey.toByteArray();
        byte[] dnskeyOwner = dnskeyRecord.name.getBytes();
        byte[] combined = new byte[dnskeyOwner.length + dnskeyData.length];
        System.arraycopy(dnskeyOwner, 0, combined, 0, dnskeyOwner.length);
        System.arraycopy(dnskeyData, 0, combined, dnskeyOwner.length, dnskeyData.length);
        byte[] digest;
        try {
            digest = digestCalculator.digest(combined);
        } catch (Exception e) {
            return new AlgorithmExceptionThrownReason(ds.digestType, "DS", dnskeyRecord, e);
        }

        if (!ds.digestEquals(digest)) {
            throw new DNSSECValidationFailedException(dnskeyRecord, "SEP is not properly signed by parent DS!");
        }
        return null;
    }

    public UnverifiedReason verify(List<Record<? extends Data>> records, RRSIG rrsig, DNSKEY key) {
        SignatureVerifier signatureVerifier = algorithmMap.getSignatureVerifier(rrsig.algorithm);
        if (signatureVerifier == null) {
            return new AlgorithmNotSupportedReason(rrsig.algorithmByte, "RRSIG", records.get(0));
        }

        byte[] combine = combine(rrsig, records);
        if (signatureVerifier.verify(combine, rrsig.signature, key.getKey())) {
            return null;
        } else {
            throw new DNSSECValidationFailedException(records, "Signature is invalid.");
        }
    }

    public UnverifiedReason verifyNsec(Record<? extends Data> nsecRecord, Question q) {
        NSEC nsec = (NSEC) nsecRecord.payloadData;
        if (nsecRecord.name.equals(q.name) && !Arrays.asList(nsec.types).contains(q.type)) {
            // records with same name but different types exist
            return null;
        } else if (nsecMatches(q.name, nsecRecord.name, nsec.next)) {
            return null;
        }
        return new NSECDoesNotMatchReason(q, nsecRecord);
    }

    public UnverifiedReason verifyNsec3(CharSequence zone, Record<? extends Data> nsec3Record, Question q) {
        return verifyNsec3(DNSName.from(zone), nsec3Record, q);
    }

    public UnverifiedReason verifyNsec3(DNSName zone, Record<? extends Data> nsec3record, Question q) {
        NSEC3 nsec3 = (NSEC3) nsec3record.payloadData;
        DigestCalculator digestCalculator = algorithmMap.getNsecDigestCalculator(nsec3.hashAlgorithm);
        if (digestCalculator == null) {
            return new AlgorithmNotSupportedReason(nsec3.hashAlgorithmByte, "NSEC3", nsec3record);
        }

        byte[] bytes = nsec3hash(digestCalculator, nsec3.salt, q.name.getBytes(), nsec3.iterations);
        String s = Base32.encodeToString(bytes);
        DNSName computedNsec3Record = DNSName.from(s + "." + zone);
        if (nsec3record.name.equals(computedNsec3Record)) {
            for (TYPE type : nsec3.types) {
                if (type.equals(q.type)) {
                    return new NSECDoesNotMatchReason(q, nsec3record);
                }
            }
            return null;
        }
        if (nsecMatches(s, nsec3record.name.getHostpart(), Base32.encodeToString(nsec3.nextHashed))) {
            return null;
        }
        return new NSECDoesNotMatchReason(q, nsec3record);
    }

    static byte[] combine(RRSIG rrsig, List<Record<? extends Data>> records) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);

        // Write RRSIG without signature
        try {
            rrsig.writePartialSignature(dos);

            DNSName sigName = records.get(0).name;
            if (!sigName.isRootLabel()) {
                if (sigName.getLabelCount() < rrsig.labels) {
                    throw new DNSSECValidationFailedException("Invalid RRsig record");
                }

                if (sigName.getLabelCount() > rrsig.labels) {
                    // Expand wildcards
                    sigName = DNSName.from("*." + sigName.stripToLabels(rrsig.labels));
                }
            }

            List<byte[]> recordBytes = new ArrayList<>();
            for (Record<? extends Data> record : records) {
                Record<Data> ref = new Record<>(sigName, record.type, record.clazzValue, rrsig.originalTtl, (Data) record.payloadData);
                recordBytes.add(ref.toByteArray());
            }

            // Sort correctly (cause they might be ordered randomly)
            final int offset = sigName.size() + 10; // Where the RDATA begins
            Collections.sort(recordBytes, new Comparator<byte[]>() {
                @Override
                public int compare(byte[] b1, byte[] b2) {
                    for (int i = offset; i < b1.length && i < b2.length; i++) {
                        if (b1[i] != b2[i]) {
                            return (b1[i] & 0xFF) - (b2[i] & 0xFF);
                        }
                    }
                    return b1.length - b2.length;
                }
            });

            for (byte[] recordByte : recordBytes) {
                dos.write(recordByte);
            }
            dos.flush();
        } catch (IOException e) {
            // Never happens
            throw new RuntimeException(e);
        }
        return bos.toByteArray();
    }

    static boolean nsecMatches(String test, String lowerBound, String upperBound) {
        return nsecMatches(DNSName.from(test), DNSName.from(lowerBound), DNSName.from(upperBound));
    }

    /**
     * Tests if a nsec domain name is part of an NSEC record.
     *
     * @param test       test domain name
     * @param lowerBound inclusive lower bound
     * @param upperBound exclusive upper bound
     * @return test domain name is covered by NSEC record
     */
    static boolean nsecMatches(DNSName test, DNSName lowerBound, DNSName upperBound) {
        int lowerParts = lowerBound.getLabelCount();
        int upperParts = upperBound.getLabelCount();
        int testParts = test.getLabelCount();

        if (testParts > lowerParts && !test.isChildOf(lowerBound) && test.stripToLabels(lowerParts).compareTo(lowerBound) < 0)
            return false;
        if (testParts <= lowerParts && test.compareTo(lowerBound.stripToLabels(testParts)) < 0)
            return false;

        if (testParts > upperParts && !test.isChildOf(upperBound) && test.stripToLabels(upperParts).compareTo(upperBound) > 0)
            return false;
        if (testParts <= upperParts && test.compareTo(upperBound.stripToLabels(testParts)) >= 0)
            return false;

        return true;
    }

    static String stripToParts(String s, int parts) {
        if (s.isEmpty() && parts == 0) return s;
        if (s.isEmpty()) throw new IllegalArgumentException();
        String[] split = s.split("\\.");
        if (split.length == parts) return s;
        if (split.length < parts) throw new IllegalArgumentException();
        StringBuilder sb = new StringBuilder();
        for (int i = split.length - parts; i < split.length; i++) {
            sb.append(split[i]);
            if (i != split.length - 1) sb.append('.');
        }
        return sb.toString();
    }

    /**
     * Derived from RFC 5155 Section 5.
     *
     * @param digestCalculator the digest calculator.
     * @param salt the salt.
     * @param data the data.
     * @param iterations the number of iterations.
     * @return the NSEC3 hash.
     */
    static byte[] nsec3hash(DigestCalculator digestCalculator, byte[] salt, byte[] data, int iterations) {
        while (iterations-- >= 0) {
            byte[] combined = new byte[data.length + salt.length];
            System.arraycopy(data, 0, combined, 0, data.length);
            System.arraycopy(salt, 0, combined, data.length, salt.length);
            data = digestCalculator.digest(combined);
        }
        return data;
    }
}
