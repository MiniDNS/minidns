/*
 * Copyright 2015-2018 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.dnsname;

import static org.minidns.Assert.assertCsEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

import org.junit.jupiter.api.Test;

import org.minidns.dnslabel.DnsLabel;

public class DnsNameTest {

    @Test
    public void sizeTest() {
        assertEquals(1, DnsName.from("").size());
        assertEquals(13, DnsName.from("example.com").size());
        assertEquals(16, DnsName.from("dömäin").size());
        assertEquals(24, DnsName.from("dömäin.example").size());
    }

    @Test
    public void toByteArrayTest() {
        assertArrayEquals(new byte[] {0}, DnsName.from("").getBytes());
        assertArrayEquals(new byte[] {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}, DnsName.from("example").getBytes());
        assertArrayEquals(new byte[] {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, DnsName.from("example.com").getBytes());
        assertArrayEquals(new byte[] {14, 'x', 'n', '-', '-', 'd', 'm', 'i', 'n', '-', 'm', 'o', 'a', '0', 'i', 0}, DnsName.from("dömäin").getBytes());
    }

    @Test
    public void parseTest() throws IOException {
        byte[] test = new byte[] {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0};
        assertCsEquals("example", DnsName.parse(new DataInputStream(new ByteArrayInputStream(test)), test));
        test = new byte[] {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
        assertCsEquals("example.com", DnsName.parse(new DataInputStream(new ByteArrayInputStream(test)), test));
    }

    @Test
    public void equalsTest() {
        assertEquals(DnsName.from(""), DnsName.from("."));
    }

    @Test
    public void testStripToParts() {
        assertCsEquals(DnsName.from("www.example.com"), DnsName.from("www.example.com").stripToLabels(3));
        assertCsEquals(DnsName.from("example.com"), DnsName.from("www.example.com").stripToLabels(2));
        assertCsEquals(DnsName.from("com"), DnsName.from("www.example.com").stripToLabels(1));
        assertCsEquals(DnsName.from("."), DnsName.from("www.example.com").stripToLabels(0));
    }

    @Test
    public void testStripToPartsIllegal() {
        assertThrows(IllegalArgumentException.class, () ->
            DnsName.from("").stripToLabels(1)
        );
    }

    @Test
    public void testStripToPartsIllegalLong() {
        assertThrows(IllegalArgumentException.class, () ->
            DnsName.from("example.com").stripToLabels(3)
       );
    }

    @Test
    public void testConcact() {
        String leftString = "foo.bar.de";
        String rightString = "example.org";
        DnsName left = DnsName.from(leftString);
        DnsName right = DnsName.from(rightString);

        DnsName concated = DnsName.from(left, right);
        DnsName expected = DnsName.from(leftString + '.' + rightString);
        assertEquals(expected, concated);
    }

    @Test
    public void testFromVarargs() {
        String leftString = "leftmost.left";
        String middleString = "leftMiddle.middle.rightMiddle";
        String rightString = "right.rightMost";
        DnsName left = DnsName.from(leftString);
        DnsName middle = DnsName.from(middleString);
        DnsName right = DnsName.from(rightString);

        DnsName name = DnsName.from(left, middle, right);

        String completeString = leftString + '.' + middleString + '.' + rightString;
        assertEquals(name.getRawAce(), completeString);

        DnsName expected = DnsName.from(completeString);
        assertEquals(name, expected);
    }

    @Test
    public void caseInsenstiveCompare() {
        DnsName lowercase = DnsName.from("cs.fau.de");
        DnsName uppercase = DnsName.from("CS.fau.de");

        assertEquals(lowercase, uppercase);
    }

    @Test
    public void rawFieldsKeepCase() {
        String mixedCaseDnsName = "UP.low.UP.low.UP";
        DnsName mixedCase = DnsName.from(mixedCaseDnsName);

        assertEquals(mixedCaseDnsName, mixedCase.getRawAce());
    }

    @Test
    public void getLabelsTest() {
        final String tldLabelString = "tld";
        final String secondLevelString = "second-level-domain";
        final String thirdLevelString = "third-level-domain";
        final String dnsNameString = thirdLevelString + '.' + secondLevelString + '.' + tldLabelString;
        final DnsName dnsName = DnsName.from(dnsNameString);

        DnsLabel[] labels = dnsName.getLabels();
        assertEquals(tldLabelString, labels[0].label);
        assertEquals(secondLevelString, labels[1].label);
        assertEquals(thirdLevelString, labels[2].label);
    }

    @Test
    public void trailingDotDnsNameFromTest() {
        final String trailingDotDnsName = "foo.bar.";
        DnsName dnsName = DnsName.from(trailingDotDnsName);
        assertEquals("foo.bar", dnsName.ace);
    }

}
