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
package de.measite.minidns;

import de.measite.minidns.DNSSECConstants.DigestAlgorithm;
import de.measite.minidns.DNSSECConstants.SignatureAlgorithm;
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
import de.measite.minidns.record.NSEC3.HashAlgorithm;
import de.measite.minidns.record.OPT;
import de.measite.minidns.record.RRSIG;
import de.measite.minidns.record.SOA;
import de.measite.minidns.record.SRV;
import de.measite.minidns.record.TXT;
import de.measite.minidns.util.Base32;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;

import static de.measite.minidns.Assert.assertCsEquals;
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
        assertFalse(m.authoritativeAnswer);
        List<Record<? extends Data>> answers = m.answerSection;
        assertEquals(2, answers.size());

        Record<? extends Data> cname = answers.get(0);
        Record<? extends Data> a = answers.get(1);

        assertTrue(cname.getPayload() instanceof CNAME);
        assertEquals(TYPE.CNAME, cname.getPayload().getType());
        assertCsEquals("legacy-sun.oraclegha.com",
                     ((CNAME)(cname.getPayload())).name);

        assertCsEquals("legacy-sun.oraclegha.com", a.name);
        assertTrue(a.getPayload() instanceof A);
        assertEquals(TYPE.A, a.getPayload().getType());
        assertCsEquals("156.151.59.35", a.getPayload().toString());
    }


    @Test
    public void testAAAALookup() throws Exception {
        DNSMessage m = getMessageFromResource("google-aaaa");
        assertFalse(m.authoritativeAnswer);
        List<Record<? extends Data>> answers = m.answerSection;
        assertEquals(1, answers.size());
        Record<? extends Data> answer = answers.get(0);
        assertCsEquals("google.com", answer.name);
        assertTrue(answer.getPayload() instanceof AAAA);
        assertEquals(TYPE.AAAA, answer.getPayload().getType());
        assertCsEquals("2a00:1450:400c:c02:0:0:0:8a", answer.getPayload().toString());
    }


    @Test
    public void testMXLookup() throws Exception {
        DNSMessage m = getMessageFromResource("gmail-mx");
        assertFalse(m.authoritativeAnswer);
        List<Record<? extends Data>> answers = m.answerSection;
        assertEquals(5, answers.size());
        Map<Integer, DNSName> mxes = new TreeMap<>();
        for(Record<? extends Data> r : answers) {
            assertCsEquals("gmail.com", r.name);
            Data d = r.getPayload();
            assertTrue(d instanceof MX);
            assertEquals(TYPE.MX, d.getType());
            mxes.put(((MX)d).priority, ((MX)d).name);
        }
        assertCsEquals("gmail-smtp-in.l.google.com", mxes.get(5));
        assertCsEquals("alt1.gmail-smtp-in.l.google.com", mxes.get(10));
        assertCsEquals("alt2.gmail-smtp-in.l.google.com", mxes.get(20));
        assertCsEquals("alt3.gmail-smtp-in.l.google.com", mxes.get(30));
        assertCsEquals("alt4.gmail-smtp-in.l.google.com", mxes.get(40));
    }


    @Test
    public void testSRVLookup() throws Exception {
        DNSMessage m = getMessageFromResource("gpn-srv");
        assertFalse(m.authoritativeAnswer);
        List<Record<? extends Data>> answers = m.answerSection;
        assertEquals(1, answers.size());
        Record<? extends Data> answer = answers.get(0);
        assertTrue(answer.getPayload() instanceof SRV);
        assertEquals(TYPE.SRV, answer.getPayload().getType());
        SRV r = (SRV)(answer.getPayload());
        assertCsEquals("raven.toroid.org", r.name);
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
        List<Record<? extends Data>> answers = m.answerSection;
        for(Record<? extends Data> r : answers) {
            assertCsEquals("codinghorror.com", r.name);
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
        assertFalse(m.authoritativeAnswer);
        List<Record<? extends Data>> answers = m.answerSection;
        assertEquals(1, answers.size());
        Record<? extends Data> answer = answers.get(0);
        assertTrue(answer.getPayload() instanceof SOA);
        assertEquals(TYPE.SOA, answer.getPayload().getType());
        SOA soa = (SOA) answer.getPayload();
        assertCsEquals("orcldns1.ultradns.com", soa.mname);
        assertCsEquals("hostmaster\\@oracle.com", soa.rname);
        assertEquals(2015032404L, soa.serial);
        assertEquals(10800, soa.refresh);
        assertEquals(3600, soa.retry);
        assertEquals(1209600, soa.expire);
        assertEquals(900L, soa.minimum);
    }

    @Test
    public void testComNsLookup() throws Exception {
        DNSMessage m = getMessageFromResource("com-ns");
        assertFalse(m.authoritativeAnswer);
        assertFalse(m.authenticData);
        assertTrue(m.recursionDesired);
        assertTrue(m.recursionAvailable);
        assertTrue(m.qr);
        List<Record<? extends Data>> answers = m.answerSection;
        assertEquals(13, answers.size());
        for (Record<? extends Data> answer : answers) {
            assertCsEquals("com", answer.name);
            assertEquals(Record.CLASS.IN, answer.clazz);
            assertEquals(TYPE.NS, answer.type);
            assertEquals(112028, answer.ttl);
            assertTrue(((NS) answer.payloadData).name.ace.endsWith(".gtld-servers.net"));
        }
        List<Record<? extends Data>> arr = m.additionalSection;
        assertEquals(1, arr.size());
        EDNS edns = EDNS.fromRecord(arr.get(0));
        assertEquals(4096, edns.udpPayloadSize);
        assertEquals(0, edns.version);
    }

    @Test
    public void testRootDnskeyLookup() throws Exception {
        DNSMessage m = getMessageFromResource("root-dnskey");
        assertFalse(m.authoritativeAnswer);
        assertTrue(m.recursionDesired);
        assertTrue(m.recursionAvailable);
        List<Record<? extends Data>> answers = m.answerSection;
        assertEquals(3, answers.size());
        for (int i = 0; i < answers.size(); i++) {
            Record<? extends Data> answer = answers.get(i);
            assertCsEquals("", answer.name);
            assertEquals(19593, answer.getTtl());
            assertEquals(TYPE.DNSKEY, answer.type);
            assertEquals(TYPE.DNSKEY, answer.getPayload().getType());
            DNSKEY dnskey = (DNSKEY) answer.getPayload();
            assertEquals(3, dnskey.protocol);
            assertEquals(SignatureAlgorithm.RSASHA256, dnskey.algorithm);
            assertTrue((dnskey.flags & DNSKEY.FLAG_ZONE) > 0);
            assertEquals(dnskey.getKeyTag(), dnskey.getKeyTag());
            switch (i) {
                case 0:
                    assertTrue((dnskey.flags & DNSKEY.FLAG_SECURE_ENTRY_POINT) > 0);
                    assertEquals(260, dnskey.getKeyLength());
                    assertEquals(19036, dnskey.getKeyTag());
                    break;
                case 1:
                    assertEquals(DNSKEY.FLAG_ZONE, dnskey.flags);
                    assertEquals(132, dnskey.getKeyLength());
                    assertEquals(48613, dnskey.getKeyTag());
                    break;
                case 2:
                    assertEquals(DNSKEY.FLAG_ZONE, dnskey.flags);
                    assertEquals(132, dnskey.getKeyLength());
                    assertEquals(1518, dnskey.getKeyTag());
                    break;
            }
        }
        List<Record<? extends Data>> arr = m.additionalSection;
        assertEquals(1, arr.size());
        Record<? extends Data> opt = arr.get(0);
        EDNS edns = EDNS.fromRecord(opt);
        assertEquals(512, edns.udpPayloadSize);
        assertEquals(0, edns.version);
    }

    @Test
    public void testComDsAndRrsigLookup() throws Exception {
        DNSMessage m = getMessageFromResource("com-ds-rrsig");
        assertFalse(m.authoritativeAnswer);
        assertTrue(m.recursionDesired);
        assertTrue(m.recursionAvailable);
        List<Record<? extends Data>> answers = m.answerSection;
        assertEquals(2, answers.size());

        assertEquals(TYPE.DS, answers.get(0).type);
        assertEquals(TYPE.DS, answers.get(0).payloadData.getType());
        DS ds = (DS) answers.get(0).payloadData;
        assertEquals(30909, ds.keyTag);
        assertEquals(SignatureAlgorithm.RSASHA256, ds.algorithm);
        assertEquals(DigestAlgorithm.SHA256, ds.digestType);
        assertCsEquals("E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766",
                ds.getDigestHex());

        assertEquals(TYPE.RRSIG, answers.get(1).type);
        assertEquals(TYPE.RRSIG, answers.get(1).payloadData.getType());
        RRSIG rrsig = (RRSIG) answers.get(1).payloadData;
        assertEquals(TYPE.DS, rrsig.typeCovered);
        assertEquals(SignatureAlgorithm.RSASHA256, rrsig.algorithm);
        assertEquals(1, rrsig.labels);
        assertEquals(86400, rrsig.originalTtl);
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        assertCsEquals("20150629170000", dateFormat.format(rrsig.signatureExpiration));
        assertCsEquals("20150619160000", dateFormat.format(rrsig.signatureInception));
        assertEquals(48613, rrsig.keyTag);
        assertCsEquals("", rrsig.signerName);
        assertEquals(128, rrsig.signature.length);

        List<Record<? extends Data>> arr = m.additionalSection;
        assertEquals(1, arr.size());
        assertEquals(TYPE.OPT, arr.get(0).getPayload().getType());
        Record<? extends Data> opt = arr.get(0);
        EDNS edns = EDNS.fromRecord(opt);
        assertEquals(512, edns.udpPayloadSize);
        assertEquals(0, edns.version);
        assertTrue(edns.dnssecOk);
    }

    @Test
    public void testExampleNsecLookup() throws Exception {
        DNSMessage m = getMessageFromResource("example-nsec");
        List<Record<? extends Data>> answers = m.answerSection;
        assertEquals(1, answers.size());
        assertEquals(TYPE.NSEC, answers.get(0).type);
        assertEquals(TYPE.NSEC, answers.get(0).payloadData.getType());
        NSEC nsec = (NSEC) answers.get(0).getPayload();
        assertCsEquals("www.example.com", nsec.next);
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
        assertEquals(0, m.answerSection.size());
        List<Record<? extends Data>> records = m.authoritySection;
        assertEquals(8, records.size());
        for (Record<? extends Data> record : records) {
            if (record.type == TYPE.NSEC3) {
                assertEquals(TYPE.NSEC3, record.getPayload().getType());
                NSEC3 nsec3 = (NSEC3) record.payloadData;
                assertEquals(HashAlgorithm.SHA1, nsec3.hashAlgorithm);
                assertEquals(1, nsec3.flags);
                assertEquals(0, nsec3.iterations);
                assertEquals(0, nsec3.salt.length);
                switch (record.name.ace) {
                    case "CK0POJMG874LJREF7EFN8430QVIT8BSM.com":
                        assertCsEquals("CK0QFMDQRCSRU0651QLVA1JQB21IF7UR", Base32.encodeToString(nsec3.nextHashed));
                        assertArrayContentEquals(new TYPE[]{TYPE.NS, TYPE.SOA, TYPE.RRSIG, TYPE.DNSKEY, TYPE.NSEC3PARAM}, nsec3.types);
                        break;
                    case "V2I33UBTHNVNSP9NS85CURCLSTFPTE24.com":
                        assertCsEquals("V2I4KPUS7NGDML5EEJU3MVHO26GKB6PA", Base32.encodeToString(nsec3.nextHashed));
                        assertArrayContentEquals(new TYPE[]{TYPE.NS, TYPE.DS, TYPE.RRSIG}, nsec3.types);
                        break;
                    case "3RL20VCNK6KV8OT9TDIJPI0JU1SS6ONS.com":
                        assertCsEquals("3RL3UFVFRUE94PV5888AIC2TPS0JA9V2", Base32.encodeToString(nsec3.nextHashed));
                        assertArrayContentEquals(new TYPE[]{TYPE.NS, TYPE.DS, TYPE.RRSIG}, nsec3.types);
                        break;
                }
            }
        }
    }

    private static void assertArrayContentEquals(Object[] expect, Object[] value) {
        assertEquals(expect.length, value.length);
        List<Object> list = new ArrayList<Object>(Arrays.asList(expect));
        for (Object type : value) {
            assertTrue(list.remove(type));
        }
        assertTrue(list.isEmpty());
    }

    @Test
    public void testMessageSelfQuestionReconstruction() throws Exception {
        DNSMessage.Builder dmb = DNSMessage.builder();
        dmb.setQuestion(new Question("www.example.com", TYPE.A));
        dmb.setRecursionDesired(true);
        dmb.setId(42);
        dmb.setQrFlag(true);
        DNSMessage message = new DNSMessage(dmb.build().toArray());

        assertEquals(1, message.questions.size());
        assertEquals(0, message.answerSection.size());
        assertEquals(0, message.additionalSection.size());
        assertEquals(0, message.authoritySection.size());
        assertTrue(message.recursionDesired);
        assertTrue(message.qr);
        assertEquals(42, message.id);
        assertCsEquals("www.example.com", message.questions.get(0).name);
        assertEquals(TYPE.A, message.questions.get(0).type);
    }

    @Test
    public void testMessageSelfEasyAnswersReconstruction() throws Exception {
        DNSMessage.Builder dmb = DNSMessage.builder();
        dmb.addAnswer(record("www.example.com", a("127.0.0.1")))
           .addAnswer(record("www.example.com", ns("example.com")));
        dmb.setRecursionAvailable(true);
        dmb.setCheckingDisabled(true);
        dmb.setQrFlag(false);
        dmb.setId(43);
        DNSMessage message = new DNSMessage(dmb.build().toArray());

        assertEquals(0, message.questions.size());
        assertEquals(2, message.answerSection.size());
        assertEquals(0, message.additionalSection.size());
        assertEquals(0, message.authoritySection.size());
        assertTrue(message.recursionAvailable);
        assertFalse(message.authenticData);
        assertTrue(message.checkingDisabled);
        assertFalse(message.qr);
        assertEquals(43, message.id);
        assertCsEquals("www.example.com", message.answerSection.get(0).name);
        assertEquals(TYPE.A, message.answerSection.get(0).type);
        assertCsEquals("127.0.0.1", message.answerSection.get(0).payloadData.toString());
        assertCsEquals("www.example.com", message.answerSection.get(1).name);
        assertEquals(TYPE.NS, message.answerSection.get(1).type);
        assertCsEquals("example.com.", message.answerSection.get(1).payloadData.toString());
    }

    @Test
    public void testMessageSelfComplexReconstruction() throws Exception {
        DNSMessage.Builder dmb = DNSMessage.builder();
        dmb.addQuestion(new Question("www.example.com", TYPE.NS));
        dmb.addAnswer(record("www.example.com", ns("ns.example.com")));
        dmb.addAdditionalResourceRecord(record("ns.example.com", a("127.0.0.1")));
        dmb.addNameserverRecords(record("ns.example.com", aaaa("2001::1")));
        dmb.setOpcode(DNSMessage.OPCODE.QUERY);
        dmb.setResponseCode(DNSMessage.RESPONSE_CODE.NO_ERROR);
        dmb.setRecursionAvailable(false);
        dmb.setAuthoritativeAnswer(true);
        dmb.setAuthenticData(true);
        dmb.setQrFlag(false);
        dmb.setId(43);
        DNSMessage message = new DNSMessage(dmb.build().toArray());

        assertEquals(1, message.questions.size());
        assertEquals(1, message.answerSection.size());
        assertEquals(1, message.additionalSection.size());
        assertEquals(1, message.authoritySection.size());

        assertFalse(message.recursionAvailable);
        assertTrue(message.authenticData);
        assertFalse(message.checkingDisabled);
        assertFalse(message.qr);
        assertTrue(message.authoritativeAnswer);
        assertEquals(43, message.id);
        assertEquals(DNSMessage.OPCODE.QUERY, message.opcode);
        assertEquals(DNSMessage.RESPONSE_CODE.NO_ERROR, message.responseCode);

        assertCsEquals("www.example.com", message.questions.get(0).name);
        assertEquals(TYPE.NS, message.questions.get(0).type);

        assertCsEquals("www.example.com", message.answerSection.get(0).name);
        assertEquals(TYPE.NS, message.answerSection.get(0).type);
        assertCsEquals("ns.example.com.", message.answerSection.get(0).payloadData.toString());

        assertCsEquals("ns.example.com", message.additionalSection.get(0).name);
        assertEquals(TYPE.A, message.additionalSection.get(0).type);
        assertCsEquals("127.0.0.1", message.additionalSection.get(0).payloadData.toString());

        assertCsEquals("ns.example.com", message.authoritySection.get(0).name);
        assertEquals(TYPE.AAAA, message.authoritySection.get(0).type);
        assertCsEquals("2001:0:0:0:0:0:0:1", message.authoritySection.get(0).payloadData.toString());
    }

    @Test
    public void testMessageSelfTruncatedReconstruction() throws Exception {
        DNSMessage.Builder dmb = DNSMessage.builder();
        dmb.setTruncated(true);
        dmb.setQrFlag(false);
        dmb.setId(44);
        DNSMessage message = new DNSMessage(dmb.build().toArray());
        assertEquals(44, message.id);
        assertFalse(message.qr);
        assertTrue(message.truncated);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testMessageSelfOptRecordReconstructione() throws Exception {
        DNSMessage.Builder m = DNSMessage.builder();
        m.addAdditionalResourceRecord(record("www.example.com", a("127.0.0.1")));
        m.getEdnsBuilder().setUdpPayloadSize(512).setDnssecOk();
        DNSMessage message = new DNSMessage(m.build().toArray());

        assertEquals(2, message.additionalSection.size());
        assertCsEquals("www.example.com", message.additionalSection.get(0).name);
        assertEquals(TYPE.A, message.additionalSection.get(0).type);
        assertCsEquals("127.0.0.1", message.additionalSection.get(0).payloadData.toString());
        assertCsEquals("EDNS: version: 0, flags: do; udp: 512", new EDNS((Record<OPT>) message.additionalSection.get(1)).toString());
    }

    @Test
    public void testEmptyMessageToString() throws Exception {
        // toString() should never throw an exception or be null
        DNSMessage message = DNSMessage.builder().build();
        assertNotNull(message.toString());
    }

    @Test
    public void testFilledMessageToString() throws Exception {
        // toString() should never throw an exception or be null
        DNSMessage.Builder message = DNSMessage.builder();
        message.setOpcode(DNSMessage.OPCODE.QUERY);
        message.setResponseCode(DNSMessage.RESPONSE_CODE.NO_ERROR);
        message.setId(1337);
        message.setAuthoritativeAnswer(true);
        message.addQuestion(new Question("www.example.com", TYPE.A));
        message.addAnswer(record("www.example.com", a("127.0.0.1")));
        message.addNameserverRecords(record("example.com", ns("ns.example.com")));
        message.addAdditionalResourceRecord(record("ns.example.com", a("127.0.0.1")));
        message.getEdnsBuilder().setUdpPayloadSize(512);
        assertNotNull(message.build().toString());
    }

    @Test
    public void testEmptyMessageTerminalOutput() throws Exception {
        // asTerminalOutput() follows a certain design, however it might change in the future.
        // Once asTerminalOutput() is changed, it might be required to update this test routine.
        DNSMessage.Builder message = DNSMessage.builder();
        message.setOpcode(DNSMessage.OPCODE.QUERY);
        message.setResponseCode(DNSMessage.RESPONSE_CODE.NO_ERROR);
        message.setId(1337);
        assertNotNull(message.build().asTerminalOutput());
    }

    @Test
    public void testFilledMessageTerminalOutput() throws Exception {
        // asTerminalOutput() follows a certain design, however it might change in the future.
        // Once asTerminalOutput() is changed, it might be required to update this test routine.
        DNSMessage.Builder message = DNSMessage.builder();
        message.setOpcode(DNSMessage.OPCODE.QUERY);
        message.setResponseCode(DNSMessage.RESPONSE_CODE.NO_ERROR);
        message.setId(1337);
        message.setAuthoritativeAnswer(true);
        message.addQuestion(new Question("www.example.com", TYPE.A));
        message.addAnswer(record("www.example.com", a("127.0.0.1")));
        message.addNameserverRecords(record("example.com", ns("ns.example.com")));
        message.addAdditionalResourceRecord(record("ns.example.com", a("127.0.0.1")));
        message.getEdnsBuilder().setUdpPayloadSize(512);
        assertNotNull(message.build().asTerminalOutput());
    }
}
