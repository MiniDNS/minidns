package de.measite.minidns;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;

import java.util.Map;
import java.util.TreeMap;

import org.junit.Test;

import de.measite.minidns.record.Data;

import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.MX;
import de.measite.minidns.record.SRV;


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
 
        DNSMessage result = DNSMessage.parse(outputStream.toByteArray());

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
        assertEquals("legacy-sun.oraclegha.com",
                     ((CNAME)(answers[cname].getPayload())).getName());

        assertEquals("legacy-sun.oraclegha.com", answers[1-cname].getName());
        assertTrue(answers[1-cname].getPayload() instanceof A);
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
            mxes.put(((MX)d).getPriority(), ((MX)d).getName());
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
        SRV r = (SRV)(answers[0].getPayload());
        assertEquals("raven.toroid.org", r.getName());
        assertEquals(5222, r.getPort());
        assertEquals(0, r.getPriority());
    }
}
