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

import java.io.IOException;
import java.util.Iterator;

import de.measite.minidns.Record;
import de.measite.minidns.cache.LRUCache;
import de.measite.minidns.dnssec.DNSSECClient;
import de.measite.minidns.dnssec.DNSSECMessage;
import de.measite.minidns.dnssec.DNSSECValidationFailedException;
import de.measite.minidns.dnssec.UnverifiedReason;

import static org.junit.Assert.assertFalse;

public class DNSSECTest {

    @IntegrationTest
    public static void testVerisignDaneBadSig() throws Exception {
        DNSSECClient client = new DNSSECClient(new LRUCache(1024));
        assertFalse(client.query("_443._tcp.bad-sig.dane.verisignlabs.com", Record.TYPE.TLSA).authenticData);
    }

    @IntegrationTest
    public static void testUniDueSigOk() throws IOException {
        DNSSECClient client = new DNSSECClient(new LRUCache(1024));
        assertAuthentic(client.queryDnssec("sigok.verteiltesysteme.net", Record.TYPE.A));
    }

    @IntegrationTest(expected = DNSSECValidationFailedException.class)
    public static void testUniDueSigFail() throws IOException {
        DNSSECClient client = new DNSSECClient(new LRUCache(1024));
        client.query("sigfail.verteiltesysteme.net", Record.TYPE.A);
    }

    @IntegrationTest
    public static void testCloudFlare() throws IOException {
        DNSSECClient client = new DNSSECClient(new LRUCache(1024));
        assertAuthentic(client.queryDnssec("www.cloudflare-dnssec-auth.com", Record.TYPE.A));
    }

    private static void assertAuthentic(DNSSECMessage dnssecMessage) {
        if (dnssecMessage.authenticData) return;

        StringBuilder sb = new StringBuilder();
        sb.append("Answer should contain authentic data while it does not. Reasons:\n");
        for (Iterator<UnverifiedReason> it = dnssecMessage.getUnverifiedReasons().iterator(); it.hasNext(); ) {
            UnverifiedReason unverifiedReason = it.next();
            sb.append(unverifiedReason);
            if (it.hasNext()) sb.append('\n');
        }
        throw new AssertionError(sb.toString());
    }
}
