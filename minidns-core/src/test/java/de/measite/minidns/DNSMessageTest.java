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

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.DNSKEY;
import de.measite.minidns.record.DS;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.MX;
import de.measite.minidns.record.NS;
import de.measite.minidns.record.NSEC;
import de.measite.minidns.record.NSEC3;
import de.measite.minidns.record.OPT;
import de.measite.minidns.record.RRSIG;
import de.measite.minidns.record.SOA;
import de.measite.minidns.record.SRV;
import de.measite.minidns.record.TXT;
import de.measite.minidns.util.Base32;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;

import static de.measite.minidns.DNSWorld.a;
import static de.measite.minidns.DNSWorld.aaaa;
import static de.measite.minidns.DNSWorld.ns;
import static de.measite.minidns.DNSWorld.record;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
        assertEquals(TYPE.CNAME, answers[cname].getPayload().getType());
        assertEquals("legacy-sun.oraclegha.com",
                     ((CNAME)(answers[cname].getPayload())).name);

        assertEquals("legacy-sun.oraclegha.com", answers[1-cname].getName());
        assertTrue(answers[1 - cname].getPayload() instanceof A);
        assertEquals(TYPE.A, answers[1 - cname].getPayload().getType());
        assertEquals("156.151.59.35", answers[1 - cname].getPayload().toString());
    }


    @Test
    public void testAAAALookup() throws Exception {
        DNSMessage m = getMessageFromResource("google-aaaa");
        assertFalse(m.isAuthoritativeAnswer());
        Record[] answers = m.getAnswers();
        assertEquals(1, answers.length);
        assertEquals("google.com", answers[0].getName());
        assertTrue(answers[0].getPayload() instanceof AAAA);
        assertEquals(TYPE.AAAA, answers[0].getPayload().getType());
        assertEquals("2a00:1450:400c:c02:0:0:0:8a", answers[0].getPayload().toString());
    }


    @Test
    public void testMXLookup() throws Exception {
        DNSMessage m = getMessageFromResource("gmail-mx");
        assertFalse(m.isAuthoritativeAnswer());
        Record[] answers = m.getAnswers();
        assertEquals(5, answers.length);
        Map<Integer, String> mxes = new TreeMap<>();
        for(Record r : answers) {
            assertEquals("gmail.com", r.getName());
            Data d = r.getPayload();
            assertTrue(d instanceof MX);
            assertEquals(TYPE.MX, d.getType());
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
        assertEquals(TYPE.SRV, answers[0].getPayload().getType());
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
            assertEquals(TYPE.TXT, d.getType());
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
        assertEquals(TYPE.SOA, answers[0].getPayload().getType());
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
            assertEquals(TYPE.NS, answer.type);
            assertEquals(112028, answer.ttl);
            assertTrue(((NS) answer.payloadData).name.endsWith(".gtld-servers.net"));
        }
        Record[] arr = m.getAdditionalResourceRecords();
        assertEquals(1, arr.length);
        Record opt = arr[0];
        assertEquals(4096, OPT.readEdnsUdpPayloadSize(opt));
        assertEquals(0, OPT.readEdnsVersion(opt));
    }

    @Test
    public void testRootDnskeyLookup() throws Exception {
        DNSMessage m = getMessageFromResource("root-dnskey");
        assertFalse(m.isAuthoritativeAnswer());
        assertTrue(m.isRecursionDesired());
        assertTrue(m.isRecursionAvailable());
        Record[] answers = m.getAnswers();
        assertEquals(3, answers.length);
        for (int i = 0; i < answers.length; i++) {
            Record answer = answers[i];
            assertEquals("", answer.getName());
            assertEquals(19593, answer.getTtl());
            assertEquals(TYPE.DNSKEY, answer.type);
            assertEquals(TYPE.DNSKEY, answer.getPayload().getType());
            DNSKEY dnskey = (DNSKEY) answer.getPayload();
            assertEquals(3, dnskey.protocol);
            assertEquals(8, dnskey.algorithm);
            assertTrue((dnskey.flags & DNSKEY.FLAG_ZONE) > 0);
            assertEquals(dnskey.getKeyTag(), dnskey.getKeyTag());
            switch (i) {
                case 0:
                    assertTrue((dnskey.flags & DNSKEY.FLAG_SECURE_ENTRY_POINT) > 0);
                    assertEquals(260, dnskey.key.length);
                    assertEquals(19036, dnskey.getKeyTag());
                    break;
                case 1:
                    assertEquals(DNSKEY.FLAG_ZONE, dnskey.flags);
                    assertEquals(132, dnskey.key.length);
                    assertEquals(48613, dnskey.getKeyTag());
                    break;
                case 2:
                    assertEquals(DNSKEY.FLAG_ZONE, dnskey.flags);
                    assertEquals(132, dnskey.key.length);
                    assertEquals(1518, dnskey.getKeyTag());
                    break;
            }
        }
        Record[] arr = m.getAdditionalResourceRecords();
        assertEquals(1, arr.length);
        Record opt = arr[0];
        assertEquals(512, OPT.readEdnsUdpPayloadSize(opt));
        assertEquals(0, OPT.readEdnsVersion(opt));
    }

    @Test
    public void testComDsAndRrsigLookup() throws Exception {
        DNSMessage m = getMessageFromResource("com-ds-rrsig");
        assertFalse(m.isAuthoritativeAnswer());
        assertTrue(m.isRecursionDesired());
        assertTrue(m.isRecursionAvailable());
        Record[] answers = m.getAnswers();
        assertEquals(2, answers.length);

        assertEquals(TYPE.DS, answers[0].type);
        assertEquals(TYPE.DS, answers[0].payloadData.getType());
        DS ds = (DS) answers[0].payloadData;
        assertEquals(30909, ds.keyTag);
        assertEquals(8, ds.algorithm);
        assertEquals(2, ds.digestType);
        assertEquals("E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766",
                new BigInteger(1, ds.digest).toString(16).toUpperCase());

        assertEquals(TYPE.RRSIG, answers[1].type);
        assertEquals(TYPE.RRSIG, answers[1].payloadData.getType());
        RRSIG rrsig = (RRSIG) answers[1].payloadData;
        assertEquals(TYPE.DS, rrsig.typeCovered);
        assertEquals(8, rrsig.algorithm);
        assertEquals(1, rrsig.labels);
        assertEquals(86400, rrsig.originalTtl);
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        assertEquals("20150629170000", dateFormat.format(rrsig.signatureExpiration));
        assertEquals("20150619160000", dateFormat.format(rrsig.signatureInception));
        assertEquals(48613, rrsig.keyTag);
        assertEquals("", rrsig.signerName);
        assertEquals(128, rrsig.signature.length);

        Record[] arr = m.getAdditionalResourceRecords();
        assertEquals(1, arr.length);
        assertEquals(TYPE.OPT, arr[0].getPayload().getType());
        Record opt = arr[0];
        assertEquals(512, OPT.readEdnsUdpPayloadSize(opt));
        assertEquals(0, OPT.readEdnsVersion(opt));
        assertTrue((OPT.readEdnsFlags(opt) & OPT.FLAG_DNSSEC_OK) > 0);
    }

    @Test
    public void testExampleNsecLookup() throws Exception {
        DNSMessage m = getMessageFromResource("example-nsec");
        Record[] answers = m.getAnswers();
        assertEquals(1, answers.length);
        assertEquals(TYPE.NSEC, answers[0].type);
        assertEquals(TYPE.NSEC, answers[0].payloadData.getType());
        NSEC nsec = (NSEC) answers[0].getPayload();
        assertEquals("www.example.com", nsec.next);
        ArrayList<TYPE> types = new ArrayList<>(Arrays.asList(
                TYPE.A, TYPE.NS, TYPE.SOA, TYPE.TXT,
                TYPE.AAAA, TYPE.RRSIG, TYPE.NSEC, TYPE.DNSKEY));

        for (TYPE type : nsec.types) {
            assertTrue(types.remove(type));
        }

        assertTrue(types.isEmpty());
    }

    @Test
    public void testComNsec3Lookup() throws Exception {
        DNSMessage m = getMessageFromResource("com-nsec3");
        assertEquals(0, m.getAnswers().length);
        Record[] records = m.getNameserverRecords();
        assertEquals(8, records.length);
        for (Record record : records) {
            if (record.type == TYPE.NSEC3) {
                assertEquals(TYPE.NSEC3, record.getPayload().getType());
                NSEC3 nsec3 = (NSEC3) record.payloadData;
                assertEquals(1, nsec3.hashAlgorithm);
                assertEquals(1, nsec3.flags);
                assertEquals(0, nsec3.iterations);
                assertEquals(0, nsec3.salt.length);
                switch (record.name) {
                    case "CK0POJMG874LJREF7EFN8430QVIT8BSM.com":
                        assertEquals("CK0QFMDQRCSRU0651QLVA1JQB21IF7UR", Base32.encodeToString(nsec3.nextHashed));
                        assertArrayContentEquals(new TYPE[]{TYPE.NS, TYPE.SOA, TYPE.RRSIG, TYPE.DNSKEY, TYPE.NSEC3PARAM}, nsec3.types);
                        break;
                    case "V2I33UBTHNVNSP9NS85CURCLSTFPTE24.com":
                        assertEquals("V2I4KPUS7NGDML5EEJU3MVHO26GKB6PA", Base32.encodeToString(nsec3.nextHashed));
                        assertArrayContentEquals(new TYPE[]{TYPE.NS, TYPE.DS, TYPE.RRSIG}, nsec3.types);
                        break;
                    case "3RL20VCNK6KV8OT9TDIJPI0JU1SS6ONS.com":
                        assertEquals("3RL3UFVFRUE94PV5888AIC2TPS0JA9V2", Base32.encodeToString(nsec3.nextHashed));
                        assertArrayContentEquals(new TYPE[]{TYPE.NS, TYPE.DS, TYPE.RRSIG}, nsec3.types);
                        break;
                }
            }
        }
    }

    private void assertArrayContentEquals(Object[] expect, Object[] value) {
        assertEquals(expect.length, value.length);
        List<Object> list = new ArrayList<Object>(Arrays.asList(expect));
        for (Object type : value) {
            assertTrue(list.remove(type));
        }
        assertTrue(list.isEmpty());
    }

    @Test
    public void testMessageSelfQuestionReconstruction() throws Exception {
        DNSMessage message = new DNSMessage();
        message.setQuestions(new Question("www.example.com", TYPE.A));
        message.setRecursionDesired(true);
        message.setId(42);
        message.setQuery(true);
        message = new DNSMessage(message.toArray());

        assertEquals(1, message.getQuestions().length);
        assertEquals(0, message.getAnswers().length);
        assertEquals(0, message.getAdditionalResourceRecords().length);
        assertEquals(0, message.getNameserverRecords().length);
        assertTrue(message.isRecursionDesired());
        assertTrue(message.isQuery());
        assertEquals(42, message.getId());
        assertEquals("www.example.com", message.questions[0].name);
        assertEquals(TYPE.A, message.questions[0].type);
    }

    @Test
    public void testMessageSelfEasyAnswersReconstruction() throws Exception {
        DNSMessage message = new DNSMessage();
        message.answers = new Record[]{
                record("www.example.com", a("127.0.0.1")), 
                record("www.example.com", ns("example.com"))};
        message.setRecursionAvailable(true);
        message.setCheckDisabled(true);
        message.setQuery(false);
        message.setId(43);
        message = new DNSMessage(message.toArray());

        assertEquals(0, message.getQuestions().length);
        assertEquals(2, message.getAnswers().length);
        assertEquals(0, message.getAdditionalResourceRecords().length);
        assertEquals(0, message.getNameserverRecords().length);
        assertTrue(message.isRecursionAvailable());
        assertFalse(message.isAuthenticData());
        assertTrue(message.isCheckDisabled());
        assertFalse(message.isQuery());
        assertEquals(43, message.getId());
        assertEquals("www.example.com", message.answers[0].name);
        assertEquals(TYPE.A, message.answers[0].type);
        assertEquals("127.0.0.1", message.answers[0].payloadData.toString());
        assertEquals("www.example.com", message.answers[1].name);
        assertEquals(TYPE.NS, message.answers[1].type);
        assertEquals("example.com.", message.answers[1].payloadData.toString());
    }

    @Test
    public void testMessageSelfComplexReconstruction() throws Exception {
        DNSMessage message = new DNSMessage();
        message.questions = new Question[]{new Question("www.example.com", TYPE.NS)};
        message.answers = new Record[]{record("www.example.com", ns("ns.example.com"))};
        message.additionalResourceRecords = new Record[]{record("ns.example.com", a("127.0.0.1"))};
        message.nameserverRecords = new Record[]{record("ns.example.com", aaaa("2001::1"))};
        message.opcode = DNSMessage.OPCODE.QUERY;
        message.responseCode = DNSMessage.RESPONSE_CODE.NO_ERROR;
        message.setRecursionAvailable(false);
        message.setAuthoritativeAnswer(true);
        message.setAuthenticData(true);
        message.setQuery(false);
        message.setId(43);
        message = new DNSMessage(message.toArray());

        assertEquals(1, message.getQuestions().length);
        assertEquals(1, message.getAnswers().length);
        assertEquals(1, message.getAdditionalResourceRecords().length);
        assertEquals(1, message.getNameserverRecords().length);

        assertFalse(message.isRecursionAvailable());
        assertTrue(message.isAuthenticData());
        assertFalse(message.isCheckDisabled());
        assertFalse(message.isQuery());
        assertTrue(message.isAuthoritativeAnswer());
        assertEquals(43, message.getId());
        assertEquals(DNSMessage.OPCODE.QUERY, message.getOpcode());
        assertEquals(DNSMessage.RESPONSE_CODE.NO_ERROR, message.getResponseCode());

        assertEquals("www.example.com", message.questions[0].name);
        assertEquals(TYPE.NS, message.questions[0].type);

        assertEquals("www.example.com", message.answers[0].name);
        assertEquals(TYPE.NS, message.answers[0].type);
        assertEquals("ns.example.com.", message.answers[0].payloadData.toString());

        assertEquals("ns.example.com", message.additionalResourceRecords[0].name);
        assertEquals(TYPE.A, message.additionalResourceRecords[0].type);
        assertEquals("127.0.0.1", message.additionalResourceRecords[0].payloadData.toString());

        assertEquals("ns.example.com", message.nameserverRecords[0].name);
        assertEquals(TYPE.AAAA, message.nameserverRecords[0].type);
        assertEquals("2001:0:0:0:0:0:0:1", message.nameserverRecords[0].payloadData.toString());
    }

    @Test
    public void testMessageSelfTruncatedReconstruction() throws Exception {
        DNSMessage message = new DNSMessage();
        message.setTruncated(true);
        message.setQuery(false);
        message.setId(44);
        message = new DNSMessage(message.toArray());
        assertEquals(44, message.getId());
        assertFalse(message.isQuery());
        assertTrue(message.isTruncated());
    }

    @Test
    public void testMessageSelfOptRecordReconstructione() throws Exception {
        DNSMessage message = new DNSMessage();
        message.additionalResourceRecords = new Record[]{record("www.example.com", a("127.0.0.1"))};
        message.setOptPseudoRecord(512, OPT.FLAG_DNSSEC_OK);
        message = new DNSMessage(message.toArray());

        assertEquals(2, message.additionalResourceRecords.length);
        assertEquals("www.example.com", message.additionalResourceRecords[0].name);
        assertEquals(TYPE.A, message.additionalResourceRecords[0].type);
        assertEquals("127.0.0.1", message.additionalResourceRecords[0].payloadData.toString());
        assertEquals("EDNS: version: 0, flags: do; udp: 512", OPT.optRecordToString(message.additionalResourceRecords[1]));
    }

    @Test
    public void testEmptyMessageToString() throws Exception {
        // toString() should never throw an exception or be null
        DNSMessage message = new DNSMessage();
        assertNotNull(message.toString());
    }

    @Test
    public void testFilledMessageToString() throws Exception {
        // toString() should never throw an exception or be null
        DNSMessage message = new DNSMessage();
        message.opcode = DNSMessage.OPCODE.QUERY;
        message.responseCode = DNSMessage.RESPONSE_CODE.NO_ERROR;
        message.setId(1337);
        message.setAuthoritativeAnswer(true);
        message.questions = new Question[]{new Question("www.example.com", TYPE.A)};
        message.answers = new Record[]{record("www.example.com", a("127.0.0.1"))};
        message.nameserverRecords = new Record[]{record("example.com", ns("ns.example.com"))};
        message.additionalResourceRecords = new Record[]{record("ns.example.com", a("127.0.0.1"))};
        message.setOptPseudoRecord(512, 0);
        assertNotNull(message.toString());
    }

    @Test
    public void testEmptyMessageTerminalOutput() throws Exception {
        // asTerminalOutput() follows a certain design, however it might change in the future.
        // Once asTerminalOutput() is changed, it might be required to update this test routine.
        DNSMessage message = new DNSMessage();
        message.opcode = DNSMessage.OPCODE.QUERY;
        message.responseCode = DNSMessage.RESPONSE_CODE.NO_ERROR;
        message.setId(1337);
        assertNotNull(message.asTerminalOutput());
    }

    @Test
    public void testFilledMessageTerminalOutput() throws Exception {
        // asTerminalOutput() follows a certain design, however it might change in the future.
        // Once asTerminalOutput() is changed, it might be required to update this test routine.
        DNSMessage message = new DNSMessage();
        message.opcode = DNSMessage.OPCODE.QUERY;
        message.responseCode = DNSMessage.RESPONSE_CODE.NO_ERROR;
        message.setId(1337);
        message.setAuthoritativeAnswer(true);
        message.questions = new Question[]{new Question("www.example.com", TYPE.A)};
        message.answers = new Record[]{record("www.example.com", a("127.0.0.1"))};
        message.nameserverRecords = new Record[]{record("example.com", ns("ns.example.com"))};
        message.additionalResourceRecords = new Record[]{record("ns.example.com", a("127.0.0.1"))};
        message.setOptPseudoRecord(512, 0);
        assertNotNull(message.asTerminalOutput());
    }
}
