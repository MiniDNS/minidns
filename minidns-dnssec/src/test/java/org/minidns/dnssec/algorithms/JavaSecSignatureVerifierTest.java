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

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class JavaSecSignatureVerifierTest {

    @Test
    public void testToDerSignatureNoPadding() {
        byte[] r = { 0x12, 0x34 };
        byte[] s = { 0x56, 0x78 };
        byte[] expected = { 0x30, 8, 0x02, 2, 0x12, 0x34, 0x02, 2, 0x56, 0x78 };
        assertArrayEquals(expected, JavaSecSignatureVerifier.toDerSignature(r, s));
    }

    @Test
    public void testToDerSignatureHighBitSet() {
        byte[] r = { (byte) 0x80, 0x01 };
        byte[] s = { (byte) 0xff, (byte) 0xff };
        byte[] expected = { 0x30, 10, 0x02, 3, 0x00, (byte) 0x80, 0x01, 0x02, 3, 0x00, (byte) 0xff, (byte) 0xff };
        assertArrayEquals(expected, JavaSecSignatureVerifier.toDerSignature(r, s));
    }

    @Test
    public void testToDerSignatureRedundantLeadingZeros() {
        // See https://github.com/MiniDNS/minidns/issues/151
        byte[] r = { 0x00, 0x44, 0x01 };
        byte[] s = { 0x00, 0x00, 0x00, 0x7f };
        byte[] expected = { 0x30, 7, 0x02, 2, 0x44, 0x01, 0x02, 1, 0x7f };
        assertArrayEquals(expected, JavaSecSignatureVerifier.toDerSignature(r, s));
    }

    @Test
    public void testToDerSignatureLeadingZerosFollowedByHighBit() {
        byte[] r = { 0x00, (byte) 0x80, 0x01 };
        byte[] s = { 0x00, 0x00, (byte) 0x90 };
        byte[] expected = { 0x30, 9, 0x02, 3, 0x00, (byte) 0x80, 0x01, 0x02, 2, 0x00, (byte) 0x90 };
        assertArrayEquals(expected, JavaSecSignatureVerifier.toDerSignature(r, s));
    }

    @Test
    public void testToDerSignatureTooLong() {
        byte[] r = new byte[64];
        byte[] s = new byte[64];
        Arrays.fill(r, (byte) 0x01);
        Arrays.fill(s, (byte) 0x01);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> JavaSecSignatureVerifier.toDerSignature(r, s));
        assertEquals("The DER encoding of r (64 bytes) and s (64 bytes) requires a SEQUENCE length of 132 bytes,"
                + " but only up to 127 bytes (DER short form length) are supported", e.getMessage());
    }

    @Test
    public void testToDerSignatureZero() {
        byte[] r = { 0x00, 0x00 };
        byte[] s = { 0x00 };
        byte[] expected = { 0x30, 6, 0x02, 1, 0x00, 0x02, 1, 0x00 };
        assertArrayEquals(expected, JavaSecSignatureVerifier.toDerSignature(r, s));
    }
}
