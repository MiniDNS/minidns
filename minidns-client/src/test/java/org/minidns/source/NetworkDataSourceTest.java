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
import org.minidns.dnsmessage.DNSMessage;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

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

    @Test
    public void socketClosedByDefaultTest() throws SocketException {
        final DatagramSocket dummySocket = new DatagramSocket() {
            boolean closed = false;

            @Override
            public synchronized void close() {
                closed = true;
            }

            @Override
            public boolean isClosed() {
                return closed;
            }
        };
        class TestNetworkDataSource extends NetworkDataSource {
            @Override
            protected DatagramSocket createDatagramSocket() {
                return dummySocket;
            }
        }
        TestNetworkDataSource world = new TestNetworkDataSource();
        // Everything has to be cached as this is going to throw a RuntimeException somewhere
        try {
            world.query(DNSMessage.builder().build(), null, 53);
        } catch (Exception ignored) {}

        assertTrue(dummySocket.isClosed());
    }

    @Test
    public void socketNotClosedTest() throws SocketException {
        final DatagramSocket dummySocket = new DatagramSocket() {
            boolean closed = false;

            @Override
            public synchronized void close() {
                closed = true;
            }

            @Override
            public boolean isClosed() {
                return closed;
            }
        };
        class TestNetworkDataSource extends NetworkDataSource {
            @Override
            protected DatagramSocket createDatagramSocket() {
                return dummySocket;
            }

            @Override
            public boolean shouldCloseSocketAfterQuery() {
                return false;
            }
        }
        TestNetworkDataSource world = new TestNetworkDataSource();
        // Everything has to be cached as this is going to throw a RuntimeException somewhere
        try {
            world.query(DNSMessage.builder().build(), null, 53);
        } catch (Exception ignored) {}

        assertFalse(dummySocket.isClosed());
    }

    @Test
    public void socketNotClosedNoOverrideTest() throws SocketException {
        final DatagramSocket dummySocket = new DatagramSocket() {
            boolean closed = false;

            @Override
            public synchronized void close() {
                closed = true;
            }

            @Override
            public boolean isClosed() {
                return closed;
            }
        };
        class TestNetworkDataSource extends NetworkDataSource {
            @Override
            protected DatagramSocket createDatagramSocket() {
                return dummySocket;
            }
        }
        TestNetworkDataSource world = new TestNetworkDataSource();
        world.setCloseSocketAfterQuery(false);
        // Everything has to be cached as this is going to throw a RuntimeException somewhere
        try {
            world.query(DNSMessage.builder().build(), null, 53);
        } catch (Exception ignored) {}

        assertFalse(dummySocket.isClosed());
    }
}
