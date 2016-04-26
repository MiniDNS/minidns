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

import de.measite.minidns.DNSSECConstants.SignatureAlgorithm;
import de.measite.minidns.dnssec.DNSSECValidationFailedException;
import org.junit.Test;

import static de.measite.minidns.dnssec.DNSSECWorld.generatePrivateKey;
import static de.measite.minidns.dnssec.DNSSECWorld.publicKey;
import static de.measite.minidns.dnssec.DNSSECWorld.sign;

public class DSASingatureVerifierTest extends SignatureVerifierTest {
    private static final SignatureAlgorithm ALGORITHM = SignatureAlgorithm.DSA;

    @Test
    public void testDSA1024Valid() {
        verifierTest(1024, ALGORITHM);
    }

    @Test
    public void testDSA512Valid() {
        verifierTest(512, ALGORITHM);
    }


    @Test(expected = DNSSECValidationFailedException.class)
    public void testDSAIllegalSignature() {
        assertSignatureValid(publicKey(ALGORITHM, generatePrivateKey(ALGORITHM, 1024)), ALGORITHM, new byte[]{0x0});
    }

    @Test(expected = DNSSECValidationFailedException.class)
    public void testDSAIllegalPublicKey() {
        assertSignatureValid(new byte[]{0x0}, ALGORITHM, sign(generatePrivateKey(ALGORITHM, 1024), ALGORITHM, sample));
    }

    @Test
    public void testDSAWrongSignature() {
        assertSignatureInvalid(publicKey(ALGORITHM, generatePrivateKey(ALGORITHM, 1024)), ALGORITHM, sign(generatePrivateKey(ALGORITHM, 1024), ALGORITHM, sample));
    }

}
