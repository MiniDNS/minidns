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
package org.minidns.source;

import org.junit.Test;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsqueryresult.DnsQueryResult;

import java.io.IOException;
import java.net.InetAddress;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class NetworkDataSourceTest {

    @Test
    public void udpTruncatedTcpFallbackTest() throws IOException {
        final int tcpResponseId = 42;
        class TestNetworkDataSource extends NetworkDataSource {
            boolean lastQueryUdp = false;

            @Override
            protected DnsMessage queryUdp(DnsMessage message, InetAddress address, int port) throws IOException {
                assertFalse(lastQueryUdp);
                lastQueryUdp = true;
                DnsMessage.Builder msg = DnsMessage.builder();
                msg.setTruncated(true);
                return msg.build();
            }

            @Override
            protected DnsMessage queryTcp(DnsMessage message, InetAddress address, int port) throws IOException {
                assertTrue(lastQueryUdp);
                lastQueryUdp = false;
                return DnsMessage.builder().setId(tcpResponseId).build();
            }
        }

        TestNetworkDataSource world = new TestNetworkDataSource();
        DnsQueryResult result = world.query(DnsMessage.builder().build(), null, 53);
        assertEquals(tcpResponseId, result.response.id);
        assertFalse(world.lastQueryUdp);
    }
}
