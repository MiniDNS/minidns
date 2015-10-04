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
import de.measite.minidns.dnssec.SignatureVerifier;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public abstract class JavaSecSignatureVerifier implements SignatureVerifier {
    private final KeyFactory keyFactory;
    private final String signatureAlgorithm;

    public JavaSecSignatureVerifier(String keyAlgorithm, String signatureAlgorithm) throws NoSuchAlgorithmException {
        keyFactory = KeyFactory.getInstance(keyAlgorithm);
        this.signatureAlgorithm = signatureAlgorithm;

        // Verify signature algorithm to be valid
        Signature.getInstance(signatureAlgorithm);
    }

    public KeyFactory getKeyFactory() {
        return keyFactory;
    }

    @Override
    public boolean verify(byte[] content, byte[] rrsigData, byte[] key) {
        try {
            PublicKey publicKey = getPublicKey(key);
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initVerify(publicKey);
            signature.update(content);
            return signature.verify(getSignature(rrsigData));
        } catch (NoSuchAlgorithmException e) {
            // We checked against this before, it should never happen!
            throw new IllegalStateException();
        } catch (InvalidKeyException | SignatureException | ArithmeticException e) {
            throw new DNSSECValidationFailedException("Validating signature failed", e);
        }
    }

    protected abstract byte[] getSignature(byte[] rrsigData);

    protected abstract PublicKey getPublicKey(byte[] key);
}
