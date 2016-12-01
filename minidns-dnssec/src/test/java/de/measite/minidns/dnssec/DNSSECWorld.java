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

import de.measite.minidns.DNSMessage;
import de.measite.minidns.DNSName;
import de.measite.minidns.DNSWorld;
import de.measite.minidns.Record;
import de.measite.minidns.DNSSECConstants.DigestAlgorithm;
import de.measite.minidns.DNSSECConstants.SignatureAlgorithm;
import de.measite.minidns.dnssec.algorithms.AlgorithmMap;
import de.measite.minidns.record.DLV;
import de.measite.minidns.record.DNSKEY;
import de.measite.minidns.record.DS;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.NSEC;
import de.measite.minidns.record.RRSIG;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class DNSSECWorld extends DNSWorld {
    public static Zone signedRootZone(SignedRRSet... rrSets) {
        return new Zone("", null, merge(rrSets));
    }

    public static Zone signedZone(String zoneName, String nsName, String nsIp, SignedRRSet... records) {
        try {
            return signedZone(zoneName, InetAddress.getByAddress(nsName, parseIpV4(nsIp)), records);
        } catch (UnknownHostException e) {
            // This will never happen, as we already ensured the validity of the IP address by using parseIpV4()
            throw new RuntimeException(e);
        }
    }

    public static Zone signedZone(String zoneName, InetAddress address, SignedRRSet... rrSets) {
        return new Zone(zoneName, address, merge(rrSets));
    }

    public static List<Record<? extends Data>> merge(SignedRRSet... rrSets) {
        List<Record<? extends Data>> recordList = new ArrayList<>();
        for (SignedRRSet rrSet : rrSets) {
            recordList.add(rrSet.signature);
            recordList.addAll(Arrays.asList(rrSet.records));
        }
        return recordList;
    }

    @SuppressWarnings("unchecked")
    public static SignedRRSet sign(DNSKEY key, String signerName, PrivateKey privateKey, SignatureAlgorithm algorithm, Record<? extends Data>... records) {
        return new SignedRRSet(records, rrsigRecord(key, signerName, privateKey, algorithm, records));
    }

    @SuppressWarnings("unchecked")
    public static SignedRRSet sign(PrivateKey privateKey, RRSIG rrsig, Record<? extends Data>... records) {
        return new SignedRRSet(records, rrsigRecord(privateKey, rrsig, records));
    }

    public static class SignedRRSet {
        Record<? extends Data>[] records;
        Record<? extends Data> signature;

        public SignedRRSet(Record<? extends Data>[] records, Record<? extends Data> signature) {
            this.records = records;
            this.signature = signature;
        }
    }

    @SuppressWarnings("unchecked")
    public static Record<? extends Data> rrsigRecord(DNSKEY key, String signerName, PrivateKey privateKey, SignatureAlgorithm algorithm, Record<? extends Data>... records) {
        Record.TYPE typeCovered = records[0].type;
        String name = records[0].name.ace;
        int labels = name.isEmpty() ? 0 : name.split("\\.").length;
        long originalTtl = records[0].ttl;
        Date signatureExpiration = new Date(System.currentTimeMillis() + 14 * 24 * 60 * 60 * 1000);
        Date signatureInception = new Date(System.currentTimeMillis() - 14 * 24 * 60 * 60 * 1000);
        RRSIG rrsig = rrsig(typeCovered, algorithm, labels, originalTtl, signatureExpiration, signatureInception,
                key.getKeyTag(), signerName, new byte[0]);
        return rrsigRecord(privateKey, rrsig, records);
    }

    @SuppressWarnings("unchecked")
    public static Record<? extends Data> rrsigRecord(PrivateKey privateKey, RRSIG rrsig, Record<? extends Data>... records) {
        byte[] bytes = Verifier.combine(rrsig, Arrays.asList(records));
        return record(records[0].name, rrsig.originalTtl, rrsig(rrsig.typeCovered, rrsig.algorithm, rrsig.labels, rrsig.originalTtl,
                rrsig.signatureExpiration, rrsig.signatureInception, rrsig.keyTag, rrsig.signerName,
                sign(privateKey, rrsig.algorithm, bytes)));
    }

    public static DS ds(String name, DigestAlgorithm digestType, DNSKEY dnskey) {
        return ds(DNSName.from(name), digestType, dnskey);
    }

    public static DS ds(DNSName name, DigestAlgorithm digestType, DNSKEY dnskey) {
        return ds(dnskey.getKeyTag(), dnskey.algorithm, digestType, calculateDsDigest(name, digestType, dnskey));
    }

    public static DLV dlv(String name, DigestAlgorithm digestType, DNSKEY dnskey) {
        return dlv(DNSName.from(name), digestType, dnskey);
    }

    public static DLV dlv(DNSName name, DigestAlgorithm digestType, DNSKEY dnskey) {
        return dlv(dnskey.getKeyTag(), dnskey.algorithm, digestType, calculateDsDigest(name, digestType, dnskey));
    }

    public static byte[] calculateDsDigest(DNSName name, DigestAlgorithm digestType, DNSKEY dnskey) {
        DigestCalculator digestCalculator = AlgorithmMap.INSTANCE.getDsDigestCalculator(digestType);

        byte[] dnskeyData = dnskey.toByteArray();
        byte[] dnskeyOwner = name.getBytes();
        byte[] combined = new byte[dnskeyOwner.length + dnskeyData.length];
        System.arraycopy(dnskeyOwner, 0, combined, 0, dnskeyOwner.length);
        System.arraycopy(dnskeyData, 0, combined, dnskeyOwner.length, dnskeyData.length);
        return digestCalculator.digest(combined);
    }

    @SuppressWarnings("deprecation")
    public static byte[] sign(PrivateKey privateKey, SignatureAlgorithm algorithm, byte[] content) {
        try {
            Signature signature;
            switch (algorithm) {
                case RSAMD5:
                    signature = Signature.getInstance("MD5withRSA");
                    break;
                case RSASHA1:
                case RSASHA1_NSEC3_SHA1:
                    signature = Signature.getInstance("SHA1withRSA");
                    break;
                case RSASHA256:
                    signature = Signature.getInstance("SHA256withRSA");
                    break;
                case RSASHA512:
                    signature = Signature.getInstance("SHA512withRSA");
                    break;
                case DSA:
                case DSA_NSEC3_SHA1:
                    signature = Signature.getInstance("SHA1withDSA");
                    break;
                default:
                    throw new RuntimeException(algorithm + " algorithm not yet supported by DNSSECWorld");
            }
            signature.initSign(privateKey);
            signature.update(content);
            byte[] bytes = signature.sign();
            switch (algorithm) {
                case DSA:
                case DSA_NSEC3_SHA1:
                    return convertAsn1ToRFC((DSAPrivateKey) privateKey, bytes);

                case RSAMD5:
                case RSASHA1:
                case RSASHA1_NSEC3_SHA1:
                case RSASHA256:
                case RSASHA512:
                default:
                    return bytes;
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Convert ASN.1 to RFC 2536.
     *
     * @param privateKey the private key.
     * @param bytes the bytes.
     * @return the RFC 2536 bytes.
     * @throws IOException if an IO error occurs.
     */
    public static byte[] convertAsn1ToRFC(DSAPrivateKey privateKey, byte[] bytes) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeByte(privateKey.getParams().getP().bitLength() / 64 - 8);
        dis.skipBytes(2);
        streamAsn1Int(dis, dos, 20);
        streamAsn1Int(dis, dos, 20);
        return bos.toByteArray();
    }

    public static void streamAsn1Int(DataInputStream dis, DataOutputStream dos, int targetLength) throws IOException {
        byte[] buf;
        dis.skipBytes(1);
        byte s_pad = (byte) (dis.readByte() - targetLength);
        if (s_pad >= 0) {
            dis.skipBytes(s_pad);
            s_pad = 0;
        } else {
            for (int i = 0; i < (1 - s_pad); i++) {
                dos.writeByte(0);
            }
        }
        buf = new byte[targetLength + s_pad];
        if (dis.read(buf) != buf.length) throw new IOException();
        dos.write(buf);
    }

    @SuppressWarnings("deprecation")
    public static PrivateKey generatePrivateKey(SignatureAlgorithm algorithm, int length) {
        switch (algorithm) {
            case RSAMD5:
            case RSASHA1:
            case RSASHA1_NSEC3_SHA1:
            case RSASHA256:
            case RSASHA512:
                return generateRSAPrivateKey(length, RSAKeyGenParameterSpec.F4);
            case DSA:
            case DSA_NSEC3_SHA1:
                return generateDSAPrivateKey(length);
            default:
                throw new RuntimeException(algorithm + " algorithm not yet supported by DNSSECWorld");
        }
    }

    public static PrivateKey generateRSAPrivateKey(int length, BigInteger publicExponent) {
        try {
            KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
            rsa.initialize(new RSAKeyGenParameterSpec(length, publicExponent));
            KeyPair keyPair = rsa.generateKeyPair();
            return keyPair.getPrivate();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey generateDSAPrivateKey(int length) {
        try {
            KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
            dsa.initialize(length);
            KeyPair keyPair = dsa.generateKeyPair();
            return keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("deprecation")
    public static byte[] publicKey(SignatureAlgorithm algorithm, PrivateKey privateKey) {
        switch (algorithm) {
            case RSAMD5:
            case RSASHA1:
            case RSASHA1_NSEC3_SHA1:
            case RSASHA256:
            case RSASHA512:
                return getRSAPublicKey((RSAPrivateCrtKey) privateKey);
            case DSA:
            case DSA_NSEC3_SHA1:
                return getDSAPublicKey((DSAPrivateKey) privateKey);
            default:
                throw new RuntimeException(algorithm + " algorithm not yet supported by DNSSECWorld");
        }
    }

    private static byte[] getDSAPublicKey(DSAPrivateKey privateKey) {
        try {
            BigInteger y = privateKey.getParams().getG().modPow(privateKey.getX(), privateKey.getParams().getP());
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            int t = privateKey.getParams().getP().bitLength() / 64 - 8;
            dos.writeByte(t);
            dos.write(toUnsignedByteArray(privateKey.getParams().getQ(), 20));
            dos.write(toUnsignedByteArray(privateKey.getParams().getP(), t * 8 + 64));
            dos.write(toUnsignedByteArray(privateKey.getParams().getG(), t * 8 + 64));
            dos.write(toUnsignedByteArray(y, t * 8 + 64));
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getRSAPublicKey(RSAPrivateCrtKey privateKey) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            byte[] exponent = toUnsignedByteArray(privateKey.getPublicExponent());
            if (exponent.length > 255) {
                dos.writeByte(0);
                dos.writeShort(exponent.length);
            } else {
                dos.writeByte(exponent.length);
            }
            dos.write(exponent);
            dos.write(toUnsignedByteArray(privateKey.getModulus()));
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] toUnsignedByteArray(BigInteger bigInteger) {
        byte[] array = bigInteger.toByteArray();
        if (array[0] == 0) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        return array;
    }

    private static byte[] toUnsignedByteArray(BigInteger bigInteger, int length) {
        byte[] array = bigInteger.toByteArray();
        if (array.length != length) {
            if (array.length == length + 1 && array[0] == 0) {
                byte[] tmp = new byte[array.length - 1];
                System.arraycopy(array, 1, tmp, 0, tmp.length);
                array = tmp;
            } else if (array.length < length) {
                byte[] tmp = new byte[length];
                System.arraycopy(array, 0, tmp, length - array.length, array.length);
                array = tmp;
            }
        }
        return array;
    }

    public static class AddressedNsecResponse implements PreparedResponse {
        final InetAddress address;
        final DNSMessage nsecMessage;

        public AddressedNsecResponse(InetAddress address, DNSMessage nsecMessage) {
            this.address = address;
            this.nsecMessage = nsecMessage;
        }

        @Override
        public boolean isResponse(DNSMessage request, InetAddress address) {
            Record<? extends Data> nsecRecord = null;
            for (Record<? extends Data> record : nsecMessage.authoritySection) {
                if (record.type == Record.TYPE.NSEC)
                    nsecRecord = record;
            }
            return address.equals(this.address) && Verifier.nsecMatches(request.getQuestion().name.ace, nsecRecord.name.ace, ((NSEC) nsecRecord.payloadData).next.ace);
        }

        @Override
        public DNSMessage getResponse() {
            return nsecMessage;
        }
    }
}
