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

import de.measite.minidns.DNSSECConstants.DigestAlgorithm;
import de.measite.minidns.dnssec.DigestCalculator;
import de.measite.minidns.record.NSEC3.HashAlgorithm;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class DigestTest extends AlgorithmTest {

    @Test
    public void testSha1DsDigest() {
        DigestCalculator dsDigestCalculator = algorithmMap.getDsDigestCalculator(DigestAlgorithm.SHA1);
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", digestHexString(dsDigestCalculator, ""));
        assertEquals("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", digestHexString(dsDigestCalculator, "test"));
        assertEquals("640ab2bae07bedc4c163f679a746f7ab7fb5d1fa", digestHexString(dsDigestCalculator, "Test"));
    }

    @Test
    public void testSha256DsDigest() {
        DigestCalculator dsDigestCalculator = algorithmMap.getDsDigestCalculator(DigestAlgorithm.SHA256);
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", digestHexString(dsDigestCalculator, ""));
        assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", digestHexString(dsDigestCalculator, "test"));
        assertEquals("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25", digestHexString(dsDigestCalculator, "Test"));
    }

    @Test
    public void testSha1nsec3Digest() {
        DigestCalculator nsecDigestCalculator = algorithmMap.getNsecDigestCalculator(HashAlgorithm.SHA1);
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", digestHexString(nsecDigestCalculator, ""));
        assertEquals("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", digestHexString(nsecDigestCalculator, "test"));
        assertEquals("640ab2bae07bedc4c163f679a746f7ab7fb5d1fa", digestHexString(nsecDigestCalculator, "Test"));
    }

    private static String digestHexString(DigestCalculator digestCalculator, String in) {
        return new BigInteger(1, digestCalculator.digest(in.getBytes())).toString(16);
    }
}
