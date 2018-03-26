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
package de.measite.minidns.util;

import static org.junit.Assert.assertEquals;

import java.net.Inet4Address;
import java.net.Inet6Address;

import org.junit.Test;

import de.measite.minidns.DNSName;

public class InetAddressUtilTest {

    // @formatter:off
    private static final String[] VALID_IPV6 = new String[] {
            "2a03:4000:2:2f5::1",
            "2001:0db8:85a3:08d3:1319:8a2e:0370:7344"
    };
    // @formatter:on

    // @formatter:off
    private static final String[] ZERO_COMPRESSED_IPV6 = new String[] {
            "2001:db8:0:0:0::1",
            "2001:db8:0:0::1",
            "2001:db8:0::1",
            "2001:db8::1"
            };
    // @formatter:on

    // @formatter:off
    private static final String[] VALID_IPV4 = new String[] {
            "192.168.0.1",
            "127.0.0.1"
    };
    // @formatter:on

    // @formatter:off
    private static final String[] INVALID_IP = new String[] {
            "2001:0db8:85a3:08d3:1319:8a2e:0370:7344:3212",
            "2001:db8:0:0:1",
            "0.0.1",
            "1.2.3.4.5",
            "foo.example",
            "foo.bar.baz.example",
    };
    // @formatter:on

    @Test
    public void testValidIpv6() {
        assertAllValidIpv6(VALID_IPV6);
        assertAllValidIpv6(ZERO_COMPRESSED_IPV6);
    }

    @Test
    public void testInvalidIpv6() {
        assertAllInvalidIpv6(INVALID_IP);
    }

    @Test
    public void testValidIpv4() {
        assertAllValidIpv4(VALID_IPV4);
    }

    @Test
    public void testInvalidIpv4() {
        assertAllInvalidIpv4(INVALID_IP);
    }

    private static void assertAllValidIpv6(String... addresses) {
        for (String address : addresses) {
            if (!InetAddressUtil.isIpV6Address(address)) {
                throw new AssertionError(address + " is not a valid IPv6 Address");
            }
        }
    }

    private static void assertAllValidIpv4(String... addresses) {
        for (String address : addresses) {
            if (!InetAddressUtil.isIpV4Address(address)) {
                throw new AssertionError(address + " is not a valid IPv4 Address");
            }
        }
    }

    private static void assertAllInvalidIpv6(String... addresses) {
        for (String address : addresses) {
            if (InetAddressUtil.isIpV6Address(address)) {
                throw new AssertionError(
                        address + " is believed to be valid IPv6 Address by isIpv6Address(), although it should not be one.");
            }
        }
    }

    private static void assertAllInvalidIpv4(String... addresses) {
        for (String address : addresses) {
            if (InetAddressUtil.isIpV4Address(address)) {
                throw new AssertionError(
                        address + " is believed to be valid IPv4 Address by isIpv4Address(), although it should not be one");
            }
        }
    }

    @Test
    public void testReverseInet6Address() {
        Inet6Address inet6Address = InetAddressUtil.ipv6From(VALID_IPV6[0]);
        DNSName reversedIpv6Address = InetAddressUtil.reverseIpAddressOf(inet6Address);
        assertEquals(DNSName.from("3.0.a.2.0.0.0.4.2.0.0.0.5.f.2.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0"), reversedIpv6Address);
    }

    @Test
    public void testReverseInet4Address() {
        Inet4Address inet4Address = InetAddressUtil.ipv4From(VALID_IPV4[0]);
        DNSName reversedIpv4Address = InetAddressUtil.reverseIpAddressOf(inet4Address);
        assertEquals(DNSName.from("1.0.168.192"), reversedIpv4Address);
    }
}
