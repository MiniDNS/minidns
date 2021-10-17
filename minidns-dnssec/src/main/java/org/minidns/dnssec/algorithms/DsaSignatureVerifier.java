/*
 * Copyright 2015-2020 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.dnssec.algorithms;

import org.minidns.dnssec.DnssecValidationFailedException.DnssecInvalidKeySpecException;
import org.minidns.record.DNSKEY;
import org.minidns.record.RRSIG;
import org.minidns.dnssec.DnssecValidationFailedException.DataMalformedException;

import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

class DsaSignatureVerifier extends JavaSecSignatureVerifier {
    private static final int LENGTH = 20;

    DsaSignatureVerifier(String algorithm) throws NoSuchAlgorithmException {
        super("DSA", algorithm);
    }

    @Override
    protected byte[] getSignature(RRSIG rrsig) throws DataMalformedException {
        DataInput dis = rrsig.getSignatureAsDataInputStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);

        try {
        // Convert RFC 2536 to ASN.1
        @SuppressWarnings("unused")
        byte t = dis.readByte();

        byte[] r = new byte[LENGTH + 1];
        dis.readFully(r, 1, LENGTH);
        int roff = 0;
        while(roff < LENGTH && r[roff] == 0 && r[roff + 1] < 0) roff++;

        byte[] s = new byte[LENGTH + 1];
        dis.readFully(s, 1, LENGTH);
        int soff = 0;
        while(soff < LENGTH && s[soff] == 0 && r[soff + 1] < 0) soff++;

        dos.writeByte(0x30);
        dos.writeByte(r.length - roff + s.length - soff + 4);

        dos.writeByte(0x2);
        dos.writeByte(r.length - roff);
        dos.write(r, roff, r.length - roff);

        dos.writeByte(0x2);
        dos.writeByte(s.length - soff);
        dos.write(s, soff, s.length - soff);
        } catch (IOException e) {
            throw new DataMalformedException(e, rrsig.getSignature());
        }

        return bos.toByteArray();
    }

    @Override
    protected PublicKey getPublicKey(DNSKEY key) throws DataMalformedException, DnssecInvalidKeySpecException {
        DataInput dis = key.getKeyAsDataInputStream();
        BigInteger subPrime, prime, base, pubKey;

        try {
            int t = dis.readUnsignedByte();

            byte[] subPrimeBytes = new byte[LENGTH];
            dis.readFully(subPrimeBytes);
            subPrime = new BigInteger(1, subPrimeBytes);

            byte[] primeBytes = new byte[64 + t * 8];
            dis.readFully(primeBytes);
            prime = new BigInteger(1, primeBytes);

            byte[] baseBytes = new byte[64 + t * 8];
            dis.readFully(baseBytes);
            base = new BigInteger(1, baseBytes);

            byte[] pubKeyBytes = new byte[64 + t * 8];
            dis.readFully(pubKeyBytes);
            pubKey = new BigInteger(1, pubKeyBytes);
        } catch (IOException e) {
            throw new DataMalformedException(e, key.getKey());
        }

        try {
            return getKeyFactory().generatePublic(new DSAPublicKeySpec(pubKey, prime, subPrime, base));
        } catch (InvalidKeySpecException e) {
            throw new DnssecInvalidKeySpecException(e);
        }
    }
}
