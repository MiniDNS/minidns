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
package de.measite.minidns.dnssec.algorithms;

import de.measite.minidns.dnssec.DNSSECValidationFailedException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

class DSASignatureVerifier extends JavaSecSignatureVerifier {
    private static final int LENGTH = 20;

    public DSASignatureVerifier(String algorithm) throws NoSuchAlgorithmException {
        super("DSA", algorithm);
    }

    @Override
    protected byte[] getSignature(byte[] rrsigData) {
        // Convert RFC 2536 to ASN.1
        try {
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(rrsigData));
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bos);

            byte t = dis.readByte();

            byte[] r = new byte[LENGTH];
            if (dis.read(r) != r.length) throw new IOException();
            int rlen = (r[0] < 0) ? LENGTH + 1 : LENGTH;

            byte[] s = new byte[LENGTH];
            if (dis.read(s) != s.length) throw new IOException();
            int slen = (s[0] < 0) ? LENGTH + 1 : LENGTH;

            dos.writeByte(0x30);
            dos.writeByte(rlen + slen + 4);

            dos.writeByte(0x2);
            dos.writeByte(rlen);
            if (rlen > LENGTH) dos.writeByte(0);
            dos.write(r);

            dos.writeByte(0x2);
            dos.writeByte(slen);
            if (slen > LENGTH) dos.writeByte(0);
            dos.write(s);

            return bos.toByteArray();
        } catch (IOException e) {
            throw new DNSSECValidationFailedException("Invalid signature!", e);
        }
    }

    protected PublicKey getPublicKey(byte[] key) {
        try {
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(key));

            int t = dis.readUnsignedByte();

            byte[] subPrimeBytes = new byte[LENGTH];
            if (dis.read(subPrimeBytes) != subPrimeBytes.length) throw new IOException();
            BigInteger subPrime = new BigInteger(1, subPrimeBytes);

            byte[] primeBytes = new byte[64 + t * 8];
            if (dis.read(primeBytes) != primeBytes.length) throw new IOException();
            BigInteger prime = new BigInteger(1, primeBytes);

            byte[] baseBytes = new byte[64 + t * 8];
            if (dis.read(baseBytes) != baseBytes.length) throw new IOException();
            BigInteger base = new BigInteger(1, baseBytes);

            byte[] pubKeyBytes = new byte[64 + t * 8];
            if (dis.read(pubKeyBytes) != pubKeyBytes.length) throw new IOException();
            BigInteger pubKey = new BigInteger(1, pubKeyBytes);

            return getKeyFactory().generatePublic(new DSAPublicKeySpec(pubKey, prime, subPrime, base));
        } catch (IOException | InvalidKeySpecException e) {
            throw new DNSSECValidationFailedException("Invalid public key!", e);
        }
    }
}
