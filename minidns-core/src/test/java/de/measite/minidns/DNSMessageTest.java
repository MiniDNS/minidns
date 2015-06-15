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
package de.measite.minidns;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Map;
import java.util.TreeMap;

import de.measite.minidns.record.OPT;
import org.junit.Test;

import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.MX;
import de.measite.minidns.record.NS;
import de.measite.minidns.record.SOA;
import de.measite.minidns.record.SRV;
import de.measite.minidns.record.TXT;

public class DNSMessageTest {


    DNSMessage getMessageFromResource(final String resourceFileName)
        throws Exception {
        InputStream inputStream =
            getClass().getResourceAsStream(resourceFileName);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        for(int readBytes = inputStream.read();
            readBytes >= 0;
            readBytes = inputStream.read())
            outputStream.write(readBytes);

        DNSMessage result = new DNSMessage(outputStream.toByteArray());

        inputStream.close();
        outputStream.close();

        assertNotNull(result);

        return result;
    }


    @Test
    public void testALookup() throws Exception {
        DNSMessage m = getMessageFromResource("sun-a");
        assertFalse(m.isAuthoritativeAnswer());
        Record[] answers = m.getAnswers();
        assertEquals(2, answers.length);

        int cname = 0;
        if(answers[1].getName().equalsIgnoreCase("www.sun.com"))
            cname = 1;
        assertTrue(answers[cname].getPayload() instanceof CNAME);
        assertEquals(Record.TYPE.CNAME, answers[cname].getPayload().getType());
        assertEquals("legacy-sun.oraclegha.com",
                     ((CNAME)(answers[cname].getPayload())).name);

        assertEquals("legacy-sun.oraclegha.com", answers[1-cname].getName());
        assertTrue(answers[1-cname].getPayload() instanceof A);
        assertEquals(Record.TYPE.A, answers[1-cname].getPayload().getType());
        assertEquals("156.151.59.35",
                     ((A)(answers[1-cname].getPayload())).toString());
    }


    @Test
    public void testAAAALookup() throws Exception {
        DNSMessage m = getMessageFromResource("google-aaaa");
        assertFalse(m.isAuthoritativeAnswer());
        Record[] answers = m.getAnswers();
        assertEquals(1, answers.length);
        assertEquals("google.com", answers[0].getName());
        assertTrue(answers[0].getPayload() instanceof AAAA);
        assertEquals(Record.TYPE.AAAA, answers[0].getPayload().getType());
        assertEquals("2a00:1450:400c:c02:0:0:0:8a",
                     ((AAAA)(answers[0].getPayload())).toString());
    }


    @Test
    public void testMXLookup() throws Exception {
        DNSMessage m = getMessageFromResource("gmail-mx");
        assertFalse(m.isAuthoritativeAnswer());
        Record[] answers = m.getAnswers();
        assertEquals(5, answers.length);
        Map<Integer, String> mxes = new TreeMap<Integer, String>();
        for(Record r : answers) {
            assertEquals("gmail.com", r.getName());
            Data d = r.getPayload();
            assertTrue(d instanceof MX);
            assertEquals(Record.TYPE.MX, d.getType());
            mxes.put(((MX)d).priority, ((MX)d).name);
        }
        assertEquals("gmail-smtp-in.l.google.com", mxes.get(5));
        assertEquals("alt1.gmail-smtp-in.l.google.com", mxes.get(10));
        assertEquals("alt2.gmail-smtp-in.l.google.com", mxes.get(20));
        assertEquals("alt3.gmail-smtp-in.l.google.com", mxes.get(30));
        assertEquals("alt4.gmail-smtp-in.l.google.com", mxes.get(40));
    }


    @Test
    public void testSRVLookup() throws Exception {
        DNSMessage m = getMessageFromResource("gpn-srv");
        assertFalse(m.isAuthoritativeAnswer());
        Record[] answers = m.getAnswers();
        assertEquals(1, answers.length);
        assertTrue(answers[0].getPayload() instanceof SRV);
        assertEquals(Record.TYPE.SRV, answers[0].getPayload().getType());
        SRV r = (SRV)(answers[0].getPayload());
        assertEquals("raven.toroid.org", r.name);
        assertEquals(5222, r.port);
        assertEquals(0, r.priority);
    }

    @Test
    public void testTXTLookup() throws Exception {
        DNSMessage m = getMessageFromResource("codinghorror-txt");
        HashSet<String> txtToBeFound = new HashSet<>();
        txtToBeFound.add("google-site-verification=2oV3cW79A6icpGf-JbLGY4rP4_omL4FOKTqRxb-Dyl4");
        txtToBeFound.add("keybase-site-verification=dKxf6T30x5EbNIUpeJcbWxUABJEnVWzQ3Z3hCumnk10");
        txtToBeFound.add("v=spf1 include:spf.mandrillapp.com ~all");
        Record[] answers = m.getAnswers();
        for(Record r : answers) {
            assertEquals("codinghorror.com", r.getName());
            Data d = r.getPayload();
            assertTrue(d instanceof TXT);
            assertEquals(Record.TYPE.TXT, d.getType());
            TXT txt = (TXT)d;
            assertTrue(txtToBeFound.contains(txt.getText()));
            txtToBeFound.remove(txt.getText());
        }
        assertEquals(txtToBeFound.size(), 0);
    }


    @Test
    public void testSoaLookup() throws Exception {
        DNSMessage m = getMessageFromResource("oracle-soa");
        assertFalse(m.isAuthoritativeAnswer());
        Record[] answers = m.getAnswers();
        assertEquals(1, answers.length);
        assertTrue(answers[0].getPayload() instanceof SOA);
        assertEquals(Record.TYPE.SOA, answers[0].getPayload().getType());
        SOA soa = (SOA) answers[0].getPayload();
        assertEquals("orcldns1.ultradns.com", soa.mname);
        assertEquals("hostmaster\\@oracle.com", soa.rname);
        assertEquals(2015032404L, soa.serial);
        assertEquals(10800, soa.refresh);
        assertEquals(3600, soa.retry);
        assertEquals(1209600, soa.expire);
        assertEquals(900L, soa.minimum);
    }

    @Test
    public void testComNsLookup() throws Exception {
        DNSMessage m = getMessageFromResource("com-ns");
        assertFalse(m.isAuthoritativeAnswer());
        assertFalse(m.isAuthenticData());
        assertTrue(m.isRecursionDesired());
        assertTrue(m.isRecursionAvailable());
        assertFalse(m.isQuery());
        Record[] answers = m.getAnswers();
        assertEquals(13, answers.length);
        for (Record answer : answers) {
            assertEquals("com", answer.name);
            assertEquals(Record.CLASS.IN, answer.clazz);
            assertEquals(Record.TYPE.NS, answer.type);
            assertEquals(112028, answer.ttl);
            assertTrue(((NS) answer.payloadData).name.endsWith(".gtld-servers.net"));
        }
        Record[] arr = m.getAdditionalResourceRecords();
        assertEquals(1, arr.length);
        Record opt = arr[0];
        assertEquals(4096, OPT.readEdnsUdpPayloadSize(opt));
        assertEquals(0, OPT.readEdnsVersion(opt));
    }
}
