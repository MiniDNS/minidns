/*
 * Copyright 2015 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.dnssec;

import de.measite.minidns.DNSSECConstants;
import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.dnssec.UnverifiedReason.AlgorithmExceptionThrownReason;
import de.measite.minidns.dnssec.UnverifiedReason.AlgorithmNotSupportedReason;
import de.measite.minidns.dnssec.UnverifiedReason.NSECDoesNotMatchReason;
import de.measite.minidns.dnssec.algorithms.AlgorithmMap;
import de.measite.minidns.record.DNSKEY;
import de.measite.minidns.record.DS;
import de.measite.minidns.record.NSEC;
import de.measite.minidns.record.NSEC3;
import de.measite.minidns.record.RRSIG;
import de.measite.minidns.util.Base32;
import de.measite.minidns.util.NameUtil;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.logging.Logger;

class Verifier {
    private Logger LOGGER = Logger.getLogger(Verifier.class.getName());

    private AlgorithmMap algorithmMap = new AlgorithmMap();

    public UnverifiedReason verify(Record dnskeyRecord, DS ds) {
        DNSKEY dnskey = (DNSKEY) dnskeyRecord.getPayload();
        DigestCalculator digestCalculator = algorithmMap.getDsDigestCalculator(ds.digestType);
        if (digestCalculator == null) {
            return new AlgorithmNotSupportedReason(DNSSECConstants.getDelegationDigestName(ds.digestType), "DS", dnskeyRecord);
        }

        byte[] dnskeyData = dnskey.toByteArray();
        byte[] dnskeyOwner = NameUtil.toByteArray(dnskeyRecord.getName());
        byte[] combined = new byte[dnskeyOwner.length + dnskeyData.length];
        System.arraycopy(dnskeyOwner, 0, combined, 0, dnskeyOwner.length);
        System.arraycopy(dnskeyData, 0, combined, dnskeyOwner.length, dnskeyData.length);
        byte[] digest;
        try {
            digest = digestCalculator.digest(combined);
        } catch (Exception e) {
            return new AlgorithmExceptionThrownReason(ds.digestType, "DS", dnskeyRecord, e);
        }

        if (!Arrays.equals(digest, ds.digest)) {
            throw new DNSSECValidationFailedException(dnskeyRecord, "SEP is not properly signed by parent DS!");
        }
        return null;
    }

    public UnverifiedReason verify(List<Record> records, RRSIG rrsig, DNSKEY key) {
        SignatureVerifier signatureVerifier = algorithmMap.getSignatureVerifier(rrsig.algorithm);
        if (signatureVerifier == null) {
            return new AlgorithmNotSupportedReason(DNSSECConstants.getSignatureAlgorithmName(rrsig.algorithm), "RRSIG", records.get(0));
        }

        byte[] combine = combine(rrsig, records);
        if (signatureVerifier.verify(combine, rrsig.signature, key.key)) {
            return null;
        } else {
            throw new DNSSECValidationFailedException(records, "Signature is invalid.");
        }
    }

    public UnverifiedReason verifyNsec(Record nsecRecord, Question q) {
        NSEC nsec = (NSEC) nsecRecord.payloadData;
        if (nsecRecord.name.equals(q.name) && !Arrays.asList(nsec.types).contains(q.type)) {
            // records with same name but different types exist
            return null;
        } else if (nsecMatches(q.name, nsecRecord.name, nsec.next)) {
            return null;
        }
        return new NSECDoesNotMatchReason(q, nsecRecord);
    }

    public UnverifiedReason verifyNsec3(String zone, Record nsec3record, Question q) {
        NSEC3 nsec3 = (NSEC3) nsec3record.payloadData;
        DigestCalculator digestCalculator = algorithmMap.getNsecDigestCalculator(nsec3.hashAlgorithm);
        if (digestCalculator == null) {
            return new AlgorithmNotSupportedReason(Integer.toString(nsec3.hashAlgorithm), "NSEC3", nsec3record);
        }

        byte[] bytes = nsec3hash(digestCalculator, nsec3.salt, NameUtil.toByteArray(q.name.toLowerCase()), nsec3.iterations);
        String s = Base32.encodeToString(bytes);
        if (nsec3record.name.equals(s + "." + zone)) {
            if (Arrays.asList(nsec3.types).contains(q.type)) {
                return new NSECDoesNotMatchReason(q, nsec3record);
            } else {
                return null;
            }
        }
        if (nsecMatches(s, nsec3record.name.split("\\.")[0], Base32.encodeToString(nsec3.nextHashed))) {
            return null;
        }
        return new NSECDoesNotMatchReason(q, nsec3record);
    }

    static byte[] combine(RRSIG rrsig, List<Record> records) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);

        // Write RRSIG without signature
        try {
            rrsig.writePartialSignature(dos);

            String sigName = records.get(0).name;
            if (!sigName.isEmpty()) {
                String[] name = sigName.split("\\.");
                if (name.length > rrsig.labels) {
                    // Expand wildcards
                    sigName = name[name.length - 1];
                    for (int i = 1; i < rrsig.labels; i++) {
                        sigName = name[name.length - i - 1] + "." + sigName;
                    }
                    sigName = "*." + sigName;
                } else if (name.length < rrsig.labels) {
                    throw new DNSSECValidationFailedException("Invalid RRsig record");
                }
            }

            List<byte[]> recordBytes = new ArrayList<>();
            for (Record record : records) {
                Record ref = new Record(sigName.toLowerCase(), record.type, record.clazzValue, rrsig.originalTtl, record.payloadData);
                recordBytes.add(ref.toByteArray());
            }

            // Sort correctly (cause they might be ordered randomly)
            final int offset = NameUtil.size(sigName) + 10; // Where the RDATA begins
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

    /**
     * Tests if a nsec domain name is part of an NSEC record.
     *
     * @param test       test domain name
     * @param lowerBound inclusive lower bound
     * @param upperBound exclusive upper bound
     * @return test domain name is covered by NSEC record
     */
    static boolean nsecMatches(String test, String lowerBound, String upperBound) {
        int lowerParts = 0, upperParts = 0, testParts = 0;
        if (!lowerBound.isEmpty()) lowerParts = lowerBound.split("\\.").length;
        if (!upperBound.isEmpty()) upperParts = upperBound.split("\\.").length;
        if (!test.isEmpty()) testParts = test.split("\\.").length;

        if (testParts > lowerParts && !test.endsWith(lowerBound) && stripToParts(test, lowerParts).compareTo(lowerBound) < 0)
            return false;
        if (testParts <= lowerParts && test.compareTo(stripToParts(lowerBound, testParts)) < 0) return false;

        if (testParts > upperParts && !test.endsWith(upperBound) && stripToParts(test, upperParts).compareTo(upperBound) > 0)
            return false;
        if (testParts <= upperParts && test.compareTo(stripToParts(upperBound, testParts)) >= 0) return false;

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
     * Derived from RFC 5155 Section 5
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
