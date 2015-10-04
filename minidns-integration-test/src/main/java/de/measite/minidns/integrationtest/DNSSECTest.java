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
package de.measite.minidns.integrationtest;

import de.measite.minidns.LRUCache;
import de.measite.minidns.Record;
import de.measite.minidns.dnssec.DNSSECClient;
import de.measite.minidns.dnssec.DNSSECValidationFailedException;

import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_ECDSAP256SHA256;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DNSSECTest {

    @IntegrationTest
    public static void testVerisignDaneBadSig() throws Exception {
        DNSSECClient client = new DNSSECClient(new LRUCache(1024));
        assertFalse(client.query("_443._tcp.bad-sig.dane.verisignlabs.com", Record.TYPE.TLSA).isAuthenticData());
    }

    @IntegrationTest
    public static void testUniDueSigOk() {
        DNSSECClient client = new DNSSECClient(new LRUCache(1024));
        assertTrue(client.query("sigok.verteiltesysteme.net", Record.TYPE.A).isAuthenticData());
    }

    @IntegrationTest(expected = DNSSECValidationFailedException.class)
    public static void testUniDueSigFail() {
        DNSSECClient client = new DNSSECClient(new LRUCache(1024));
        client.query("sigfail.verteiltesysteme.net", Record.TYPE.A);
    }

    @IntegrationTest(requiredSignatureVerifier = SIGNATURE_ALGORITHM_ECDSAP256SHA256)
    public static void testCloudFlare() {
        DNSSECClient client = new DNSSECClient(new LRUCache(1024));
        assertTrue(client.query("www.cloudflare-dnssec-auth.com", Record.TYPE.A).isAuthenticData());
    }
}
