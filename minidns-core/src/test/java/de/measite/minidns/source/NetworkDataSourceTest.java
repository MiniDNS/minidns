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
package de.measite.minidns.source;

import de.measite.minidns.DNSMessage;
import org.junit.Test;

import java.io.IOException;
import java.net.InetAddress;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class NetworkDataSourceTest {

    @Test
    public void udpTruncatedTcpFallbackTest() throws IOException {
        class TestNetworkDataSource extends NetworkDataSource {
            boolean lastQueryUdp = false;

            @Override
            protected DNSMessage queryUdp(DNSMessage message, InetAddress address, int port) throws IOException {
                assertFalse(lastQueryUdp);
                lastQueryUdp = true;
                DNSMessage.Builder msg = DNSMessage.builder();
                msg.setTruncated(true);
                return msg.build();
            }

            @Override
            protected DNSMessage queryTcp(DNSMessage message, InetAddress address, int port) throws IOException {
                assertTrue(lastQueryUdp);
                lastQueryUdp = false;
                return null;
            }
        }
        TestNetworkDataSource world = new TestNetworkDataSource();
        assertNull(world.query(DNSMessage.builder().build(), null, 53));
        assertFalse(world.lastQueryUdp);
    }
}
