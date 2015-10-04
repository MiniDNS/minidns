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
import org.junit.Test;

import java.math.BigInteger;

import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_RSAMD5;
import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_RSASHA1;
import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_RSASHA256;
import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_RSASHA512;
import static de.measite.minidns.dnssec.DNSSECWorld.generatePrivateKey;
import static de.measite.minidns.dnssec.DNSSECWorld.generateRSAPrivateKey;
import static de.measite.minidns.dnssec.DNSSECWorld.publicKey;
import static de.measite.minidns.dnssec.DNSSECWorld.sign;

public class RSASignatureVerifierTest extends SignatureVerifierTest {
    @Test
    public void testShortExponentSHA1RSAValid() {
        verifierTest(generateRSAPrivateKey(1024, BigInteger.valueOf(17)), SIGNATURE_ALGORITHM_RSASHA1);
    }

    @Test
    public void testLongExponentSHA1RSAValid() {
        verifierTest(generateRSAPrivateKey(3072, BigInteger.valueOf(256).pow(256).add(BigInteger.ONE)), SIGNATURE_ALGORITHM_RSASHA1);
    }

    @Test(expected = DNSSECValidationFailedException.class)
    public void testSHA1RSAIllegalSignature() {
        assertSignatureValid(publicKey(SIGNATURE_ALGORITHM_RSASHA1, generatePrivateKey(SIGNATURE_ALGORITHM_RSASHA1, 1024)), SIGNATURE_ALGORITHM_RSASHA1, new byte[]{0x0});
    }

    @Test(expected = DNSSECValidationFailedException.class)
    public void testSHA1RSAIllegalPublicKey() {
        assertSignatureValid(new byte[]{0x0}, SIGNATURE_ALGORITHM_RSASHA1, sign(generatePrivateKey(SIGNATURE_ALGORITHM_RSASHA1, 1024), SIGNATURE_ALGORITHM_RSASHA1, sample));
    }

    @Test
    public void testSHA1RSAWrongSignature() {
        assertSignatureInvalid(publicKey(SIGNATURE_ALGORITHM_RSASHA1, generatePrivateKey(SIGNATURE_ALGORITHM_RSASHA1, 1024)), SIGNATURE_ALGORITHM_RSASHA1, sign(generatePrivateKey(SIGNATURE_ALGORITHM_RSASHA1, 1024), SIGNATURE_ALGORITHM_RSASHA1, sample));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void testMD5RSAValid() {
        verifierTest(1024, SIGNATURE_ALGORITHM_RSAMD5);
    }

    @Test
    public void testSHA256RSAValid() {
        verifierTest(1024, SIGNATURE_ALGORITHM_RSASHA256);
    }

    @Test
    public void testSHA512RSAValid() {
        verifierTest(1024, SIGNATURE_ALGORITHM_RSASHA512);
    }
}
