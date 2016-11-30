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
package de.measite.minidns.integrationtest;

import de.measite.minidns.DNSClient;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.Record;
import de.measite.minidns.cache.LRUCache;
import de.measite.minidns.record.Data;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class CoreTest {
    @IntegrationTest
    public static void testExampleCom() throws IOException {
        DNSClient client = new DNSClient(new LRUCache(1024));
        String exampleIp4 = "93.184.216.34"; // stable?
        String exampleIp6 = "2606:2800:220:1:248:1893:25c8:1946"; // stable?
        assertEquals(client.query("example.com", Record.TYPE.A).answerSection.get(0).payloadData.toString(), exampleIp4);
        assertEquals(client.query("www.example.com", Record.TYPE.A).answerSection.get(0).payloadData.toString(), exampleIp4);
        assertEquals(client.query("example.com", Record.TYPE.AAAA).answerSection.get(0).payloadData.toString(), exampleIp6);
        assertEquals(client.query("www.example.com", Record.TYPE.AAAA).answerSection.get(0).payloadData.toString(), exampleIp6);

        DNSMessage nsRecords = client.query("example.com", Record.TYPE.NS);
        List<String> values = new ArrayList<>();
        for (Record<? extends Data> record : nsRecords.answerSection) {
            values.add(record.payloadData.toString());
        }
        Collections.sort(values);
        assertEquals(values.get(0), "a.iana-servers.net.");
        assertEquals(values.get(1), "b.iana-servers.net.");
    }

    @IntegrationTest
    public static void testTcpAnswer() throws IOException {
        DNSClient client = new DNSClient(new LRUCache(1024));
        client.setAskForDnssec(true);
        client.setDisableResultFilter(true);
        DNSMessage result = client.query("www-nsec.example.com", Record.TYPE.A);
        assertNotNull(result);
        assertTrue(result.toArray().length > 512);
    }
}
