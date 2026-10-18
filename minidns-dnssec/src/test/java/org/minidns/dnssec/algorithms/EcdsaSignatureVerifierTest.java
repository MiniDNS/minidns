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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.PrivateKey;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.minidns.dnssec.DnssecWorld.generatePrivateKey;
import static org.minidns.dnssec.DnssecWorld.publicKey;
import static org.minidns.dnssec.DnssecWorld.sign;

public class EcdsaSignatureVerifierTest extends SignatureVerifierTest {

    private static final int MAX_ATTEMPTS = 100_000;

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = { "ECDSAP256SHA256", "ECDSAP384SHA384" })
    public void testEcdsaValid(SignatureAlgorithm algorithm) throws DnssecValidationFailedException {
        PrivateKey privateKey = generatePrivateKey(algorithm, 0);
        // Verify a bunch of signatures, so that we likely also hit signatures where r or s has leading zeros or the
        // high bit set.
        for (int i = 0; i < 1000; i++) {
            verifierTest(privateKey, algorithm);
        }
    }

    /**
     * Signatures where r or s start with a zero byte, followed by a byte whose high bit is not set, must be encoded
     * without the leading zero byte in ASN.1 DER. See <a href="https://github.com/MiniDNS/minidns/issues/151">MiniDNS
     * issue #151</a>.
     *
     * @param algorithm the ECDSA algorithm.
     * @throws DnssecValidationFailedException if the validation failed.
     */
    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = { "ECDSAP256SHA256", "ECDSAP384SHA384" })
    public void testEcdsaRedundantLeadingZeroValid(SignatureAlgorithm algorithm) throws DnssecValidationFailedException {
        assertSignatureWithLeadingZeroValid(algorithm, false);
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = { "ECDSAP256SHA256", "ECDSAP384SHA384" })
    public void testEcdsaLeadingZeroFollowedByHighBitValid(SignatureAlgorithm algorithm) throws DnssecValidationFailedException {
        assertSignatureWithLeadingZeroValid(algorithm, true);
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = { "ECDSAP256SHA256", "ECDSAP384SHA384" })
    public void testEcdsaWrongSignature(SignatureAlgorithm algorithm) throws DnssecValidationFailedException {
        byte[] sample = getRandomBytes();
        assertSignatureInvalid(publicKey(algorithm, generatePrivateKey(algorithm, 0)), algorithm,
                sign(generatePrivateKey(algorithm, 0), algorithm, sample), sample);
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = { "ECDSAP256SHA256", "ECDSAP384SHA384" })
    public void testEcdsaIllegalSignature(SignatureAlgorithm algorithm) {
        byte[] sample = new byte[] { 0x0 };
        assertThrows(DataMalformedException.class, () ->
            assertSignatureValid(publicKey(algorithm, generatePrivateKey(algorithm, 0)), algorithm, sample, sample)
        );
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = { "ECDSAP256SHA256", "ECDSAP384SHA384" })
    public void testEcdsaIllegalPublicKey(SignatureAlgorithm algorithm) {
        byte[] sample = getRandomBytes();
        assertThrows(DataMalformedException.class, () ->
            assertSignatureValid(new byte[] { 0x0 }, algorithm, sign(generatePrivateKey(algorithm, 0), algorithm, sample), sample)
        );
    }

    private static void assertSignatureWithLeadingZeroValid(SignatureAlgorithm algorithm, boolean followedByHighBit)
            throws DnssecValidationFailedException {
        PrivateKey privateKey = generatePrivateKey(algorithm, 0);
        byte[] publicKey = publicKey(algorithm, privateKey);
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            byte[] sample = getRandomBytes();
            byte[] signature = sign(privateKey, algorithm, sample);
            int length = signature.length / 2;
            if (hasLeadingZero(signature, 0, followedByHighBit) || hasLeadingZero(signature, length, followedByHighBit)) {
                assertSignatureValid(publicKey, algorithm, signature, sample);
                return;
            }
        }
        fail("Unable to generate a signature with the required leading zero after " + MAX_ATTEMPTS + " attempts");
    }

    private static boolean hasLeadingZero(byte[] signature, int offset, boolean followedByHighBit) {
        if (signature[offset] != 0) {
            return false;
        }
        boolean highBitSet = (signature[offset + 1] & 0x80) != 0;
        return highBitSet == followedByHighBit;
    }
}
