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

import org.minidns.constants.DnssecConstants.SignatureAlgorithm;
import org.minidns.dnssec.DnssecValidationFailedException;
import org.minidns.dnssec.DnssecValidationFailedException.DataMalformedException;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.minidns.dnssec.DnssecWorld.generatePrivateKey;
import static org.minidns.dnssec.DnssecWorld.publicKey;
import static org.minidns.dnssec.DnssecWorld.sign;

public class DsaSingatureVerifierTest extends SignatureVerifierTest {
    private static final SignatureAlgorithm ALGORITHM = SignatureAlgorithm.DSA;

    @Test
    public void testDSA1024Valid() throws DnssecValidationFailedException {
        verifierTest(1024, ALGORITHM);
    }

    @Test
    public void testDSA512Valid() throws DnssecValidationFailedException {
        verifierTest(512, ALGORITHM);
    }

    /**
     * Signatures where r or s start with a zero byte must be encoded with the leading zero bytes removed in ASN.1
     * DER, but must keep one zero byte if the following byte has its high bit set.
     *
     * @throws DnssecValidationFailedException if the validation failed.
     */
    @Test
    public void testDSALeadingZeroValid() throws DnssecValidationFailedException {
        PrivateKey privateKey = generatePrivateKey(ALGORITHM, 1024);
        byte[] publicKey = publicKey(ALGORITHM, privateKey);
        boolean redundantLeadingZeroSeen = false, requiredLeadingZeroSeen = false;
        for (int i = 0; i < 100_000 && !(redundantLeadingZeroSeen && requiredLeadingZeroSeen); i++) {
            byte[] sample = getRandomBytes();
            byte[] signature = sign(privateKey, ALGORITHM, sample);
            // Skip the T octet, r and s are 20 bytes each.
            for (int offset : new int[] { 1, 21 }) {
                if (signature[offset] != 0) continue;

                assertSignatureValid(publicKey, ALGORITHM, signature, sample);
                if ((signature[offset + 1] & 0x80) == 0) {
                    redundantLeadingZeroSeen = true;
                } else {
                    requiredLeadingZeroSeen = true;
                }
            }
        }
        assertTrue(redundantLeadingZeroSeen && requiredLeadingZeroSeen);
    }

    @Test
    public void testDSAIllegalSignature() {
        byte[] sample = new byte[] { 0x0 };
        assertThrows(DataMalformedException.class, () ->
            assertSignatureValid(publicKey(ALGORITHM, generatePrivateKey(ALGORITHM, 1024)), ALGORITHM, sample, sample)
        );
    }

    @Test
    public void testDSAIllegalPublicKey() {
        byte[] sample = getRandomBytes();

        assertThrows(DataMalformedException.class, () ->
            assertSignatureValid(new byte[] {0x0}, ALGORITHM, sign(generatePrivateKey(ALGORITHM, 1024), ALGORITHM, sample), sample)
        );
    }

    @Test
    public void testDSAWrongSignature() throws DnssecValidationFailedException {
        byte[] sample = getRandomBytes();
        assertSignatureInvalid(publicKey(ALGORITHM, generatePrivateKey(ALGORITHM, 1024)), ALGORITHM,
                sign(generatePrivateKey(ALGORITHM, 1024), ALGORITHM, sample), sample);
    }

}
