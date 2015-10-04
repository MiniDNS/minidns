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
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;

class ECGOSTSignatureVerifier extends JavaSecSignatureVerifier {
    private static final int LENGTH = 32;
    private static ECParameterSpec SPEC = new ECParameterSpec(
            new EllipticCurve(
                    new ECFieldFp(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16)),
                    new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94", 16),
                    new BigInteger("A6", 16)
            ),
            new ECPoint(BigInteger.ONE, new BigInteger("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14", 16)),
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893", 16),
            1
    );

    public ECGOSTSignatureVerifier() throws NoSuchAlgorithmException {
        super("ECGOST3410", "GOST3411withECGOST3410");
    }

    @Override
    protected byte[] getSignature(byte[] rrsigData) {
        return rrsigData;
    }

    @Override
    protected PublicKey getPublicKey(byte[] key) {
        try {
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(key));

            byte[] xBytes = new byte[LENGTH];
            if (dis.read(xBytes) != xBytes.length) throw new IOException();
            reverse(xBytes);
            BigInteger x = new BigInteger(1, xBytes);

            byte[] yBytes = new byte[LENGTH];
            if (dis.read(yBytes) != yBytes.length) throw new IOException();
            reverse(yBytes);
            BigInteger y = new BigInteger(1, yBytes);

            return getKeyFactory().generatePublic(new ECPublicKeySpec(new ECPoint(x, y), SPEC));
        } catch (IOException | InvalidKeySpecException e) {
            throw new DNSSECValidationFailedException("Invalid public key!", e);
        }
    }

    private static void reverse(byte[] array) {
        for (int i = 0; i < array.length / 2; i++) {
            int j = array.length - i - 1;
            byte tmp = array[i];
            array[i] = array[j];
            array[j] = tmp;
        }
    }
}
