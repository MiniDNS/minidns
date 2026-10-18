/*
 * Copyright 2015-2024 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.dnssec;

import org.minidns.DnsWorld;
import org.minidns.constants.DnssecConstants.DigestAlgorithm;
import org.minidns.constants.DnssecConstants.SignatureAlgorithm;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsname.DnsName;
import org.minidns.dnssec.algorithms.AlgorithmMap;
import org.minidns.record.DLV;
import org.minidns.record.DNSKEY;
import org.minidns.record.DS;
import org.minidns.record.Data;
import org.minidns.record.NSEC;
import org.minidns.record.RRSIG;
import org.minidns.record.Record;
import org.minidns.record.Record.TYPE;
import org.minidns.util.InetAddressUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Inet4Address;
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
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DnssecWorld extends DnsWorld {

    public static final SignatureAlgorithm DEFAULT_DNSSEC_ALGORITHM = SignatureAlgorithm.RSASHA256;
    public static final DigestAlgorithm DEFAULT_DIGEST_ALGORITHM = DigestAlgorithm.SHA1;

    private static final Map<DnsName, DnssecData> DNSSEC_DATA = new HashMap<>();

    public static final class DnssecData {
        public final DnsName zone;
        public final DNSKEY ksk;
        public final PrivateKey privateKsk;
        public final DNSKEY zsk;
        public final PrivateKey privateZsk;
        public final SignatureAlgorithm signatureAlgorithm;

        private DnssecData(DnsName zone, DNSKEY ksk, PrivateKey privateKsk, DNSKEY zsk, PrivateKey privateZsk,
                SignatureAlgorithm signatureAlgorithm) {
            this.zone = zone;
            this.ksk = ksk;
            this.privateKsk = privateKsk;
            this.zsk = zsk;
            this.privateZsk = privateZsk;
            this.signatureAlgorithm = signatureAlgorithm;
        }
    }

    public static DnssecData getDnssecDataFor(CharSequence zone) {
        return getDnssecDataFor(DnsName.from(zone));
    }

    public static DnssecData getDnssecDataFor(DnsName zone) {
        DnssecData dnssecData = DNSSEC_DATA.get(zone);
        if (dnssecData != null) {
            return dnssecData;
        }

        SignatureAlgorithm algorithm = DEFAULT_DNSSEC_ALGORITHM;
        PrivateKey privateKsk = generatePrivateKey(algorithm, 2048);
        DNSKEY ksk = dnskey(DNSKEY.FLAG_ZONE | DNSKEY.FLAG_SECURE_ENTRY_POINT, algorithm, publicKey(algorithm, privateKsk));
        PrivateKey privateZsk = generatePrivateKey(algorithm, 1024);
        DNSKEY zsk = dnskey(DNSKEY.FLAG_ZONE, algorithm, publicKey(algorithm, privateZsk));
        dnssecData = new DnssecData(zone, ksk, privateKsk, zsk, privateZsk, algorithm);

        DNSSEC_DATA.put(zone, dnssecData);

        return dnssecData;
    }

    public static Zone signedRootZone(SignedRRSet... rrSets) {
        return new Zone("", null, merge(rrSets));
    }

    public static Zone signedZone(String zoneName, String nsName, String nsIp, SignedRRSet... records) {
        Inet4Address inet4Address = InetAddressUtil.ipv4From(nsIp);
        try {
            return signedZone(zoneName, InetAddress.getByAddress(nsName, inet4Address.getAddress()), records);
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

    @SuppressWarnings("varargs")
    @SafeVarargs
    public static SignedRRSet sign(DNSKEY key, String signerName, PrivateKey privateKey, SignatureAlgorithm algorithm, Record<? extends Data>... records) {
        return new SignedRRSet(records, rrsigRecord(key, signerName, privateKey, algorithm, records));
    }

    @SuppressWarnings("varargs")
    @SafeVarargs
    public static SignedRRSet sign(DNSKEY key, DnsName signerName, PrivateKey privateKey, SignatureAlgorithm algorithm, Record<? extends Data>... records) {
        return new SignedRRSet(records, rrsigRecord(key, signerName, privateKey, algorithm, records));
    }

    @SuppressWarnings("varargs")
    @SafeVarargs
    public static SignedRRSet sign(PrivateKey privateKey, RRSIG rrsig, Record<? extends Data>... records) {
        return new SignedRRSet(records, rrsigRecord(privateKey, rrsig, records));
    }

    @SafeVarargs
    public static SignedRRSet sign(CharSequence signerName, Record<? extends Data>... records) {
        return sign(DnsName.from(signerName), records);
    }

    @SuppressWarnings("varargs")
    @SafeVarargs
    public static SignedRRSet sign(DnsName signerName, Record<? extends Data>... records) {
        DnssecData dnssecData = getDnssecDataFor(signerName);

        DNSKEY dnskey;
        PrivateKey privateKey;
        final TYPE typeToSign = records[0].type;
        switch (typeToSign) {
        case DNSKEY:
            dnskey = dnssecData.ksk;
            privateKey = dnssecData.privateKsk;
            break;
        default:
            dnskey = dnssecData.zsk;
            privateKey = dnssecData.privateZsk;
            break;
        }

        // TODO: Check if all records are of type 'typeToSign'.

        return new SignedRRSet(records, rrsigRecord(dnskey, signerName, privateKey, dnssecData.signatureAlgorithm, records));
    }

    public static SignedRRSet selfSignDnskeyRrSet(CharSequence zone) {
        return selfSignDnskeyRrSet(DnsName.from(zone));
    }

    public static SignedRRSet selfSignDnskeyRrSet(DnsName zone) {
        DnssecData dnssecData = getDnssecDataFor(zone);
        return sign(zone,
                record(zone, dnssecData.ksk),
                record(zone, dnssecData.zsk));
    }

    public static class SignedRRSet {
        Record<? extends Data>[] records;
        Record<RRSIG> signature;

        public SignedRRSet(Record<? extends Data>[] records, Record<RRSIG> signature) {
            this.records = records;
            this.signature = signature;
        }
    }


    @SafeVarargs
    public static Record<RRSIG> rrsigRecord(DNSKEY key, String signerName, PrivateKey privateKey, SignatureAlgorithm algorithm, Record<? extends Data>... records) {
        return rrsigRecord(key, DnsName.from(signerName), privateKey, algorithm, records);
    }

    @SuppressWarnings({"unchecked", "JavaUtilDate"})
    public static Record<RRSIG> rrsigRecord(DNSKEY key, DnsName signerName, PrivateKey privateKey, SignatureAlgorithm algorithm, Record<? extends Data>... records) {
        Record.TYPE typeCovered = records[0].type;
        int labels = records[0].name.getLabelCount();
        long originalTtl = records[0].ttl;
        Date signatureExpiration = new Date(System.currentTimeMillis() + 14 * 24 * 60 * 60 * 1000);
        Date signatureInception = new Date(System.currentTimeMillis() - 14 * 24 * 60 * 60 * 1000);
        RRSIG rrsig = rrsig(typeCovered, algorithm, labels, originalTtl, signatureExpiration, signatureInception,
                key.getKeyTag(), signerName, new byte[0]);
        return rrsigRecord(privateKey, rrsig, records);
    }

    @SuppressWarnings("unchecked")
    public static Record<RRSIG> rrsigRecord(PrivateKey privateKey, RRSIG rrsig, Record<? extends Data>... records) {
        byte[] bytes = Verifier.combine(rrsig, Arrays.asList(records));
        return record(records[0].name, rrsig.originalTtl, rrsig(rrsig.typeCovered, rrsig.algorithm, rrsig.labels, rrsig.originalTtl,
                rrsig.signatureExpiration, rrsig.signatureInception, rrsig.keyTag, rrsig.signerName,
                sign(privateKey, rrsig.algorithm, bytes))).as(RRSIG.class);
    }

    public static Record<DS> ds(CharSequence zone) {
        return ds(DnsName.from(zone));
    }

    public static Record<DS> ds(DnsName zone) {
        DnssecData dnssecData = getDnssecDataFor(zone);
        return record(zone, ds(zone, DEFAULT_DIGEST_ALGORITHM, dnssecData.ksk));
    }

    public static DS ds(String name, DigestAlgorithm digestType, DNSKEY dnskey) {
        return ds(DnsName.from(name), digestType, dnskey);
    }

    public static DS ds(DnsName name, DigestAlgorithm digestType, DNSKEY dnskey) {
        return ds(dnskey.getKeyTag(), dnskey.algorithm, digestType, calculateDsDigest(name, digestType, dnskey));
    }

    public static DLV dlv(String name, DigestAlgorithm digestType, DNSKEY dnskey) {
        return dlv(DnsName.from(name), digestType, dnskey);
    }

    public static DLV dlv(DnsName name, DigestAlgorithm digestType, DNSKEY dnskey) {
        return dlv(dnskey.getKeyTag(), dnskey.algorithm, digestType, calculateDsDigest(name, digestType, dnskey));
    }

    public static byte[] calculateDsDigest(DnsName name, DigestAlgorithm digestType, DNSKEY dnskey) {
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
                case ECDSAP256SHA256:
                    signature = Signature.getInstance("SHA256withECDSA");
                    break;
                case ECDSAP384SHA384:
                    signature = Signature.getInstance("SHA384withECDSA");
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

                case ECDSAP256SHA256:
                case ECDSAP384SHA384:
                    return convertAsn1ToRfc6605(bytes, getEcdsaLength(algorithm));

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
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeByte(privateKey.getParams().getP().bitLength() / 64 - 8);
        dos.write(convertAsn1SignatureToFixedLength(bytes, 20));
        return bos.toByteArray();
    }

    /**
     * Convert an ASN.1 ECDSA signature to RFC 6605.
     *
     * @param bytes the ASN.1 DER encoded signature.
     * @param length the length of r and s in bytes.
     * @return the RFC 6605 bytes.
     * @throws IOException if an IO error occurs.
     */
    public static byte[] convertAsn1ToRfc6605(byte[] bytes, int length) throws IOException {
        return convertAsn1SignatureToFixedLength(bytes, length);
    }

    /**
     * Convert an ASN.1 DER encoded {@code SEQUENCE { INTEGER r, INTEGER s }} to the concatenation of r and s, each as
     * fixed-length unsigned integer.
     *
     * @param bytes the ASN.1 DER encoded signature.
     * @param length the length of r and s in bytes.
     * @return r and s as fixed-length unsigned integers.
     * @throws IOException if an IO error occurs.
     */
    private static byte[] convertAsn1SignatureToFixedLength(byte[] bytes, int length) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes));
        if (dis.readUnsignedByte() != 0x30) throw new IOException("Not an ASN.1 SEQUENCE");
        readAsn1Length(dis);
        BigInteger r = readAsn1Integer(dis);
        BigInteger s = readAsn1Integer(dis);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(toUnsignedByteArray(r, length));
        bos.write(toUnsignedByteArray(s, length));
        return bos.toByteArray();
    }

    private static BigInteger readAsn1Integer(DataInputStream dis) throws IOException {
        if (dis.readUnsignedByte() != 0x02) throw new IOException("Not an ASN.1 INTEGER");
        byte[] value = new byte[readAsn1Length(dis)];
        dis.readFully(value);
        return new BigInteger(value);
    }

    private static int readAsn1Length(DataInputStream dis) throws IOException {
        int length = dis.readUnsignedByte();
        if (length < 0x80) {
            return length;
        }
        int numBytes = length & 0x7f;
        length = 0;
        for (int i = 0; i < numBytes; i++) {
            length = (length << 8) | dis.readUnsignedByte();
        }
        return length;
    }

    private static int getEcdsaLength(SignatureAlgorithm algorithm) {
        switch (algorithm) {
            case ECDSAP256SHA256:
                return 32;
            case ECDSAP384SHA384:
                return 48;
            default:
                throw new IllegalArgumentException(algorithm + " is not an ECDSA algorithm");
        }
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
            case ECDSAP256SHA256:
                return generateECPrivateKey("secp256r1");
            case ECDSAP384SHA384:
                return generateECPrivateKey("secp384r1");
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

    /**
     * Unlike RSA and DSA private keys, EC private keys do not allow to derive the public key easily. Hence we remember
     * the public key of every generated EC private key.
     */
    private static final Map<PrivateKey, ECPublicKey> EC_PUBLIC_KEYS = new ConcurrentHashMap<>();

    public static PrivateKey generateECPrivateKey(String curveName) {
        try {
            KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
            ec.initialize(new ECGenParameterSpec(curveName));
            KeyPair keyPair = ec.generateKeyPair();
            EC_PUBLIC_KEYS.put(keyPair.getPrivate(), (ECPublicKey) keyPair.getPublic());
            return keyPair.getPrivate();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
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
            case ECDSAP256SHA256:
            case ECDSAP384SHA384:
                return getECPublicKey(privateKey, getEcdsaLength(algorithm));
            default:
                throw new RuntimeException(algorithm + " algorithm not yet supported by DNSSECWorld");
        }
    }

    private static byte[] getDSAPublicKey(DSAPrivateKey privateKey) {
        final DSAParams params = privateKey.getParams();
        final BigInteger g = params.getG();
        final BigInteger p = params.getP();
        final BigInteger q = params.getQ();
        final BigInteger x = privateKey.getX();
        final BigInteger y = g.modPow(x, p);
        final int t = p.bitLength() / 64 - 8;

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.writeByte(t);
            dos.write(toUnsignedByteArray(q, 20));
            dos.write(toUnsignedByteArray(p, t * 8 + 64));
            dos.write(toUnsignedByteArray(g, t * 8 + 64));
            dos.write(toUnsignedByteArray(y, t * 8 + 64));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return baos.toByteArray();
    }

    private static byte[] getECPublicKey(PrivateKey privateKey, int length) {
        ECPublicKey publicKey = EC_PUBLIC_KEYS.get(privateKey);
        if (publicKey == null) {
            throw new IllegalArgumentException("Unknown EC private key, it must be generated by DnssecWorld");
        }
        ECPoint w = publicKey.getW();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(toUnsignedByteArray(w.getAffineX(), length));
            baos.write(toUnsignedByteArray(w.getAffineY(), length));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return baos.toByteArray();
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
        final DnsMessage nsecMessage;
        final boolean isRootNameserver;

        // We currently do not use the whole list of NSEC records, but in the future we eventually will be.
        final List<Record<NSEC>> nsecRecords;

        public AddressedNsecResponse(InetAddress address, DnsMessage nsecMessage) {
            this.address = address;
            this.nsecMessage = nsecMessage;
            this.isRootNameserver = address.getHostName().endsWith(".root-servers.net");
            this.nsecRecords = nsecMessage.filterAuthoritySectionBy(NSEC.class);
        }

        @Override
        public boolean isResponse(DnsMessage request, InetAddress address) {
            boolean nameserverMatches;
            if (isRootNameserver) {
                nameserverMatches = address.getHostName().endsWith(".root-servers.net");
            } else {
                nameserverMatches = address.equals(this.address);
            }

            Record<NSEC> nsecRecord = nsecRecords.get(0);
            return nameserverMatches && Verifier.nsecMatches(request.getQuestion().name, nsecRecord.name, nsecRecord.payloadData.next);
        }

        @Override
        public DnsMessage getResponse() {
            return nsecMessage;
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + ": " + address + '\n'
                    + nsecMessage;
        }
    }

    public static void addNsec(DnsWorld dnsWorld, CharSequence zone, CharSequence zoneSoaNameserver,
            CharSequence owner, String nextSecure, Record.TYPE... typesCovered) {
        addNsec(dnsWorld, DnsName.from(zone), DnsName.from(zoneSoaNameserver), DnsName.from(owner),
                DnsName.from(nextSecure), typesCovered);
    }

    public static void addNsec(DnsWorld dnsWorld, DnsName zone, DnsName zoneSoaNameserver, DnsName owner, DnsName nextSecure,
            Record.TYPE... typesCovered) {
        DnssecData dnssecData = getDnssecDataFor(zone);
        PrivateKey privateKey = dnssecData.privateZsk;
        DNSKEY key = dnssecData.zsk;
        SignatureAlgorithm signatureAlgorithm = dnssecData.signatureAlgorithm;

        DnsMessage.Builder nsecAnswerBuilder = DnsMessage.builder();
        List<Record<? extends Data>> records = DnssecWorld.merge(
                                sign(key, zone, privateKey, signatureAlgorithm,
                                        record(owner, nsec(nextSecure, typesCovered))),
                                sign(key, zone, privateKey, signatureAlgorithm,
                                        record(owner, soa(zoneSoaNameserver,
                                                          DnsName.from("mailbox.of.responsible.person"),
                                                          2015081265,
                                                          7200,
                                                          3600,
                                                          1209600,
                                                          3600))));
        nsecAnswerBuilder.setNameserverRecords(records);
        nsecAnswerBuilder.setAuthoritativeAnswer(true);

        DnsMessage nsecAnswer = nsecAnswerBuilder.build();

        // Get the authoritative nameserver IP address from dns world.
        InetAddress authoritativeNameserver = dnsWorld.lookupSingleAuthoritativeNameserverForZone(zone);

        PreparedResponse preparedNsecResponse = new DnssecWorld.AddressedNsecResponse(authoritativeNameserver, nsecAnswer); 
        dnsWorld.addPreparedResponse(preparedNsecResponse);
    }
}
