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
package org.minidns.dnssec.algorithms;

import org.minidns.dnssec.DnssecValidationFailedException;
import org.minidns.dnssec.DnssecValidationFailedException.DataMalformedException;
import org.minidns.dnssec.DnssecValidationFailedException.DnssecInvalidKeySpecException;
import org.minidns.dnssec.SignatureVerifier;
import org.minidns.record.DNSKEY;
import org.minidns.record.RRSIG;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
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
    public boolean verify(byte[] content, RRSIG rrsig, DNSKEY key) throws DnssecValidationFailedException {
        try {
            PublicKey publicKey = getPublicKey(key);
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initVerify(publicKey);
            signature.update(content);
            return signature.verify(getSignature(rrsig));
        } catch (NoSuchAlgorithmException e) {
            // We checked against this before, it should never happen!
            throw new AssertionError(e);
        } catch (InvalidKeyException | SignatureException | ArithmeticException e) {
            throw new DnssecValidationFailedException("Validating signature failed", e);
        }
    }

    /**
     * Encode the two unsigned integers r and s of a DSA or ECDSA signature as ASN.1 DER
     * {@code SEQUENCE { INTEGER r, INTEGER s }}, as expected by {@link Signature#verify(byte[])}.
     * <p>
     * DER requires the minimal two's complement encoding of each INTEGER: leading zero bytes have to be removed,
     * unless they are required because the following byte has its high bit set. Strict DER parsers, like the one of
     * the SunEC provider, reject non-minimal encodings.
     * </p>
     *
     * @param r the unsigned big-endian r value.
     * @param s the unsigned big-endian s value.
     * @return the DER encoded signature.
     */
    static byte[] toDerSignature(byte[] r, byte[] s) {
        byte[] rDer = new BigInteger(1, r).toByteArray();
        byte[] sDer = new BigInteger(1, s).toByteArray();

        int sequenceLength = 2 + rDer.length + 2 + sDer.length;
        // Only the DER short form length encoding is implemented, which is sufficient for DSA (20 byte r and s) and
        // ECDSA P-256 (32 byte r and s) and P-384 (48 byte r and s).
        if (sequenceLength > 127) {
            throw new IllegalArgumentException("The DER encoding of r (" + r.length + " bytes) and s (" + s.length
                    + " bytes) requires a SEQUENCE length of " + sequenceLength
                    + " bytes, but only up to 127 bytes (DER short form length) are supported");
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream(2 + sequenceLength);
        bos.write(0x30);
        bos.write(sequenceLength);
        bos.write(0x02);
        bos.write(rDer.length);
        bos.write(rDer, 0, rDer.length);
        bos.write(0x02);
        bos.write(sDer.length);
        bos.write(sDer, 0, sDer.length);
        return bos.toByteArray();
    }

    protected abstract byte[] getSignature(RRSIG rrsig) throws DataMalformedException;

    protected abstract PublicKey getPublicKey(DNSKEY key) throws DataMalformedException, DnssecInvalidKeySpecException;
}
