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
package de.measite.minidns.dnslabel;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import de.measite.minidns.idna.MiniDnsIdna;

public class DNSLabelTest {

    @Test
    public void simpleNonReservedLdhLabelTest() {
        final String nonReservedLdhLabelString = "test";
        final DNSLabel label = DNSLabel.from(nonReservedLdhLabelString);

        assertEquals(nonReservedLdhLabelString, label.label);
        assertTrue(label instanceof NonReservedLdhLabel);
        assertEquals("NonReservedLdhLabel", label.getLabelType());
    }

    @Test
    public void aLabelTest() {
        final String uLabelString = "müller";
        final String aLabelString = MiniDnsIdna.toASCII(uLabelString);
        final DNSLabel label = DNSLabel.from(aLabelString);

        assertEquals(aLabelString, label.label);
        assertTrue(label instanceof ALabel);
        assertEquals(uLabelString, label.getInternationalizedRepresentation());
        assertEquals("ALabel", label.getLabelType());
    }

    @Test
    public void fakeALabelTest() {
        final String fakeALabelString = "xn--mller-va";
        final DNSLabel label = DNSLabel.from(fakeALabelString);

        assertEquals(fakeALabelString, label.label);
        assertTrue(label instanceof FakeALabel);
        assertEquals("FakeALabel", label.getLabelType());
    }

    @Test
    public void underscoreLabelTest() {
        final String underscoreLabelString = "_tcp";
        final DNSLabel label = DNSLabel.from(underscoreLabelString);

        assertEquals(underscoreLabelString, label.label);
        assertTrue(label instanceof UnderscoreLabel);
        assertEquals("UnderscoreLabel", label.getLabelType());
    }

    @Test
    public void leadingHyphenLabelTest() {
        final String leadingHyphenLabelString = "-foo";
        final DNSLabel label = DNSLabel.from(leadingHyphenLabelString);

        assertEquals(leadingHyphenLabelString, label.label);
        assertTrue(label instanceof LeadingOrTrailingHyphenLabel);
        assertEquals("LeadingOrTrailingHyphenLabel", label.getLabelType());
    }

    @Test
    public void trailingHyphenLabelTest() {
        final String trailingHyphenLabelString = "bar-";
        final DNSLabel label = DNSLabel.from(trailingHyphenLabelString);

        assertEquals(trailingHyphenLabelString, label.label);
        assertTrue(label instanceof LeadingOrTrailingHyphenLabel);
        assertEquals("LeadingOrTrailingHyphenLabel", label.getLabelType());
    }

    @Test
    public void otherNonLdhLabelTest() {
        final String otherNonLdhLabelString = "w@$abi";
        final DNSLabel label = DNSLabel.from(otherNonLdhLabelString);

        assertEquals(otherNonLdhLabelString, label.label);
        assertTrue(label instanceof OtherNonLdhLabel);
        assertEquals("OtherNonLdhLabel", label.getLabelType());
    }
}
