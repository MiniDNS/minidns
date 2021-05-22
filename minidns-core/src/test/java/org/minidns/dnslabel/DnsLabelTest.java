/*
 * Copyright 2015-2021 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.dnslabel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import org.minidns.idna.MiniDnsIdna;

public class DnsLabelTest {

    @Test
    public void simpleNonReservedLdhLabelTest() {
        final String nonReservedLdhLabelString = "test";
        final DnsLabel label = DnsLabel.from(nonReservedLdhLabelString);

        assertEquals(nonReservedLdhLabelString, label.label);
        assertTrue(label instanceof NonReservedLdhLabel);
        assertEquals("NonReservedLdhLabel", label.getLabelType());
    }

    @Test
    public void aLabelTest() {
        final String uLabelString = "müller";
        final String aLabelString = MiniDnsIdna.toASCII(uLabelString);
        final DnsLabel label = DnsLabel.from(aLabelString);

        assertEquals(aLabelString, label.label);
        assertTrue(label instanceof ALabel);
        assertEquals(uLabelString, label.getInternationalizedRepresentation());
        assertEquals("ALabel", label.getLabelType());
    }

    @Test
    public void fakeALabelTest() {
        final String fakeALabelString = "xn--mller-va";
        final DnsLabel label = DnsLabel.from(fakeALabelString);

        assertEquals(fakeALabelString, label.label);
        assertTrue(label instanceof FakeALabel);
        assertEquals("FakeALabel", label.getLabelType());
    }

    @Test
    public void underscoreLabelTest() {
        final String underscoreLabelString = "_tcp";
        final DnsLabel label = DnsLabel.from(underscoreLabelString);

        assertEquals(underscoreLabelString, label.label);
        assertTrue(label instanceof UnderscoreLabel);
        assertEquals("UnderscoreLabel", label.getLabelType());
    }

    @Test
    public void leadingHyphenLabelTest() {
        final String leadingHyphenLabelString = "-foo";
        final DnsLabel label = DnsLabel.from(leadingHyphenLabelString);

        assertEquals(leadingHyphenLabelString, label.label);
        assertTrue(label instanceof LeadingOrTrailingHyphenLabel);
        assertEquals("LeadingOrTrailingHyphenLabel", label.getLabelType());
    }

    @Test
    public void trailingHyphenLabelTest() {
        final String trailingHyphenLabelString = "bar-";
        final DnsLabel label = DnsLabel.from(trailingHyphenLabelString);

        assertEquals(trailingHyphenLabelString, label.label);
        assertTrue(label instanceof LeadingOrTrailingHyphenLabel);
        assertEquals("LeadingOrTrailingHyphenLabel", label.getLabelType());
    }

    @Test
    public void otherNonLdhLabelTest() {
        final String otherNonLdhLabelString = "w@$abi";
        final DnsLabel label = DnsLabel.from(otherNonLdhLabelString);

        assertEquals(otherNonLdhLabelString, label.label);
        assertTrue(label instanceof OtherNonLdhLabel);
        assertEquals("OtherNonLdhLabel", label.getLabelType());
    }

    @Test
    public void dnsLabelWildcardStringTest() {
        assertEquals("*", DnsLabel.WILDCARD_LABEL.toString());
    }
}
