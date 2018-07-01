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
package org.minidns;

import org.minidns.cache.LruCache;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsserverlookup.AbstractDnsServerLookupMechanism;
import org.minidns.dnsserverlookup.AndroidUsingExec;
import org.minidns.dnsserverlookup.AndroidUsingReflection;
import org.minidns.dnsserverlookup.DnsServerLookupMechanism;
import org.minidns.record.A;
import org.minidns.record.Record.TYPE;
import org.minidns.source.AbstractDnsDataSource;

import org.junit.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import static org.minidns.DnsWorld.a;
import static org.minidns.DnsWorld.applyStubRecords;
import static org.minidns.DnsWorld.record;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class DnsClientTest {

    @Test
    public void testLookupMechanismOrder() {
        DnsClient.addDnsServerLookupMechanism(new TestDnsServerLookupMechanism(AndroidUsingExec.INSTANCE));
        DnsClient.addDnsServerLookupMechanism(new TestDnsServerLookupMechanism(AndroidUsingReflection.INSTANCE));

        List<DnsServerLookupMechanism> expectedOrder = new ArrayList<>();
        expectedOrder.add(0, AndroidUsingExec.INSTANCE);
        expectedOrder.add(1, AndroidUsingReflection.INSTANCE);
        for (DnsServerLookupMechanism mechanism : DnsClient.LOOKUP_MECHANISMS) {
            if (expectedOrder.isEmpty()) {
                break;
            }
            DnsServerLookupMechanism shouldBeRemovedNext = expectedOrder.get(0);
            if (mechanism.getName().equals(shouldBeRemovedNext.getName())) {
                expectedOrder.remove(0);
            }
        }
        assertTrue(expectedOrder.isEmpty());
    }

    private static class TestDnsServerLookupMechanism extends AbstractDnsServerLookupMechanism {
        protected TestDnsServerLookupMechanism(DnsServerLookupMechanism lookupMechanism) {
            super(lookupMechanism.getName(), lookupMechanism.getPriority());
        }
        @Override
        public boolean isAvailable() {
            return true;
        }
        @Override
        public List<String> getDnsServerAddresses() {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testSingleRecordQuery() throws IOException {
        DnsClient client = new DnsClient(new LruCache(0));
        applyStubRecords(client, record("www.example.com", a("127.0.0.1")));
        DnsMessage response = client.query("www.example.com", TYPE.A);
        assertNotNull(response);
        assertEquals(1, response.answerSection.size());
        assertEquals(TYPE.A, response.answerSection.get(0).type);
        assertArrayEquals(new byte[]{127, 0, 0, 1}, ((A) response.answerSection.get(0).payloadData).getIp());
        response = client.query("www2.example.com", TYPE.A);
        assertNull(response);
        response = client.query("www.example.com", TYPE.CNAME);
        assertNull(response);
    }

    @Test
    public void testReturnNullSource() throws IOException {
        class NullSource extends AbstractDnsDataSource {
            boolean queried = false;

            @Override
            public DnsMessage query(DnsMessage message, InetAddress address, int port) {
                queried = true;
                return null;
            }
        }
        DnsClient client = new DnsClient(new LruCache(0));
        NullSource source = new NullSource();
        client.setDataSource(source);
        DnsMessage message = client.query("www.example.com", TYPE.A);
        assertNull(message);
        assertTrue(source.queried);
    }
}
