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

import org.junit.Before;

import de.measite.minidns.DNSSECConstants.SignatureAlgorithm;

import java.security.PrivateKey;
import java.util.Random;

import static de.measite.minidns.dnssec.DNSSECWorld.generatePrivateKey;
import static de.measite.minidns.dnssec.DNSSECWorld.publicKey;
import static de.measite.minidns.dnssec.DNSSECWorld.sign;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SignatureVerifierTest extends AlgorithmTest {
    private static Random RANDOM = new Random();
    protected byte[] sample;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        sample = new byte[1024];
        RANDOM.nextBytes(sample);
    }

    protected void verifierTest(int length, SignatureAlgorithm algorithm) {
        verifierTest(generatePrivateKey(algorithm, length), algorithm);
    }

    protected void verifierTest(PrivateKey privateKey, SignatureAlgorithm algorithm) {
        assertSignatureValid(publicKey(algorithm, privateKey), algorithm, sign(privateKey, algorithm, sample));
    }

    protected void assertSignatureValid(byte[] publicKey, SignatureAlgorithm algorithm, byte[] signature) {
        assertTrue(algorithmMap.getSignatureVerifier(algorithm).verify(sample, signature, publicKey));
    }

    protected void assertSignatureInvalid(byte[] publicKey, SignatureAlgorithm algorithm, byte[] signature) {
        assertFalse(algorithmMap.getSignatureVerifier(algorithm).verify(sample, signature, publicKey));
    }
}
