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
package de.measite.minidns.world;

import de.measite.minidns.DNSMessage;
import org.junit.Test;

import java.io.IOException;
import java.net.InetAddress;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class NetworkDNSWorldTest {

    @Test
    public void udpTruncatedTcpFallbackTest() {
        class TestNetworkWorld extends NetworkDNSWorld {
            boolean lastQueryUdp = false;

            @Override
            protected DNSMessage queryUdp(DNSMessage message, InetAddress address, int port) throws IOException {
                assertFalse(lastQueryUdp);
                lastQueryUdp = true;
                DNSMessage msg = new DNSMessage();
                msg.setTruncated(true);
                return msg;
            }

            @Override
            protected DNSMessage queryTcp(DNSMessage message, InetAddress address, int port) throws IOException {
                assertTrue(lastQueryUdp);
                lastQueryUdp = false;
                return null;
            }
        }
        TestNetworkWorld world = new TestNetworkWorld();
        assertNull(world.query(new DNSMessage(), null, 53));
        assertFalse(world.lastQueryUdp);
    }
}
