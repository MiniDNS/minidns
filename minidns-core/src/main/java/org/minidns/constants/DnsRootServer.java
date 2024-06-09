/*
 * Copyright 2015-2024 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.constants;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class DnsRootServer {

    private static final Map<Character, Inet4Address> IPV4_ROOT_SERVER_MAP = new HashMap<>();

    private static final Map<Character, Inet6Address> IPV6_ROOT_SERVER_MAP = new HashMap<>();

    protected static final Inet4Address[] IPV4_ROOT_SERVERS = new Inet4Address[] {
            rootServerInet4Address('a', 198,  41,   0,   4),
            rootServerInet4Address('b', 192, 228,  79, 201),
            rootServerInet4Address('c', 192,  33,   4,  12),
            rootServerInet4Address('d', 199,   7,  91 , 13),
            rootServerInet4Address('e', 192, 203, 230,  10),
            rootServerInet4Address('f', 192,   5,   5, 241),
            rootServerInet4Address('g', 192, 112,  36,   4),
            rootServerInet4Address('h', 198,  97, 190,  53),
            rootServerInet4Address('i', 192,  36, 148,  17),
            rootServerInet4Address('j', 192,  58, 128,  30),
            rootServerInet4Address('k', 193,   0,  14, 129),
            rootServerInet4Address('l', 199,   7,  83,  42),
            rootServerInet4Address('m', 202,  12,  27,  33),
        };

        protected static final Inet6Address[] IPV6_ROOT_SERVERS = new Inet6Address[] {
            rootServerInet6Address('a', 0x2001, 0x0503, 0xba3e, 0x0000, 0x0000, 0x000, 0x0002, 0x0030),
            rootServerInet6Address('b', 0x2001, 0x0500, 0x0084, 0x0000, 0x0000, 0x000, 0x0000, 0x000b),
            rootServerInet6Address('c', 0x2001, 0x0500, 0x0002, 0x0000, 0x0000, 0x000, 0x0000, 0x000c),
            rootServerInet6Address('d', 0x2001, 0x0500, 0x002d, 0x0000, 0x0000, 0x000, 0x0000, 0x000d),
            rootServerInet6Address('f', 0x2001, 0x0500, 0x002f, 0x0000, 0x0000, 0x000, 0x0000, 0x000f),
            rootServerInet6Address('h', 0x2001, 0x0500, 0x0001, 0x0000, 0x0000, 0x000, 0x0000, 0x0053),
            rootServerInet6Address('i', 0x2001, 0x07fe, 0x0000, 0x0000, 0x0000, 0x000, 0x0000, 0x0053),
            rootServerInet6Address('j', 0x2001, 0x0503, 0x0c27, 0x0000, 0x0000, 0x000, 0x0002, 0x0030),
            rootServerInet6Address('l', 0x2001, 0x0500, 0x0003, 0x0000, 0x0000, 0x000, 0x0000, 0x0042),
            rootServerInet6Address('m', 0x2001, 0x0dc3, 0x0000, 0x0000, 0x0000, 0x000, 0x0000, 0x0035),
        };

        private static Inet4Address rootServerInet4Address(char rootServerId, int addr0, int addr1, int addr2, int addr3) {
            Inet4Address inetAddress;
            String name = rootServerId + ".root-servers.net";
                try {
                    inetAddress = (Inet4Address) InetAddress.getByAddress(name, new byte[] { (byte) addr0, (byte) addr1, (byte) addr2,
                            (byte) addr3 });
                    IPV4_ROOT_SERVER_MAP.put(rootServerId, inetAddress);
                } catch (UnknownHostException e) {
                    // This should never happen, if it does it's our fault!
                    throw new RuntimeException(e);
                }

            return inetAddress;
        }

        private static Inet6Address rootServerInet6Address(char rootServerId, int addr0, int addr1, int addr2, int addr3, int addr4, int addr5, int addr6, int addr7) {
            Inet6Address inetAddress;
            String name = rootServerId + ".root-servers.net";
                try {
                    inetAddress = (Inet6Address) InetAddress.getByAddress(name, new byte[] {
                            // @formatter:off
                            (byte) (addr0 >> 8), (byte) addr0, (byte) (addr1 >> 8), (byte) addr1,
                            (byte) (addr2 >> 8), (byte) addr2, (byte) (addr3 >> 8), (byte) addr3,
                            (byte) (addr4 >> 8), (byte) addr4, (byte) (addr5 >> 8), (byte) addr5,
                            (byte) (addr6 >> 8), (byte) addr6, (byte) (addr7 >> 8), (byte) addr7
                            // @formatter:on
                    });
                    IPV6_ROOT_SERVER_MAP.put(rootServerId, inetAddress);
                } catch (UnknownHostException e) {
                    // This should never happen, if it does it's our fault!
                    throw new RuntimeException(e);
                }
            return inetAddress;
        }

        public static Inet4Address getRandomIpv4RootServer(Random random) {
            return IPV4_ROOT_SERVERS[random.nextInt(IPV4_ROOT_SERVERS.length)];
        }

        public static Inet6Address getRandomIpv6RootServer(Random random) {
            return IPV6_ROOT_SERVERS[random.nextInt(IPV6_ROOT_SERVERS.length)];
        }

        public static Inet4Address getIpv4RootServerById(char id) {
            return IPV4_ROOT_SERVER_MAP.get(id);
        }

        public static Inet6Address getIpv6RootServerById(char id) {
            return IPV6_ROOT_SERVER_MAP.get(id);
        }

}
