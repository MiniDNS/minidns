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
package de.measite.minidns.dnssec.algorithms;

import de.measite.minidns.dnssec.DNSSECValidationFailedException;

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

class RSASignatureVerifier extends JavaSecSignatureVerifier {
    public RSASignatureVerifier(String algorithm) throws NoSuchAlgorithmException {
        super("RSA", algorithm);
    }

    protected PublicKey getPublicKey(byte[] key) {
        DataInput dis = new DataInputStream(new ByteArrayInputStream(key));

        try {
            int exponentLength = dis.readUnsignedByte();
            int bytesRead = 1;
            if (exponentLength == 0) {
                bytesRead += 2;
                exponentLength = dis.readUnsignedShort();
            }

            byte[] exponentBytes = new byte[exponentLength];
            dis.readFully(exponentBytes);
            bytesRead += exponentLength;
            BigInteger exponent = new BigInteger(1, exponentBytes);

            byte[] modulusBytes = new byte[key.length - bytesRead];
            dis.readFully(modulusBytes);
            BigInteger modulus = new BigInteger(1, modulusBytes);

            return getKeyFactory().generatePublic(new RSAPublicKeySpec(modulus, exponent));
        } catch (IOException | InvalidKeySpecException e) {
            throw new DNSSECValidationFailedException("Invalid public key!", e);
        }
    }

    @Override
    protected byte[] getSignature(byte[] rrsigData) {
        return rrsigData;
    }
}
