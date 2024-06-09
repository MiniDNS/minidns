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
package org.minidns.integrationtest;

import java.io.IOException;
import java.util.Iterator;

import org.junit.Ignore;
import org.minidns.cache.LruCache;
import org.minidns.dnssec.DnssecClient;
import org.minidns.dnssec.DnssecQueryResult;
import org.minidns.dnssec.DnssecUnverifiedReason;
import org.minidns.dnssec.DnssecValidationFailedException;
import org.minidns.record.Record;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class DnssecTest {

    @Ignore
    @IntegrationTest
    public static void testOarcDaneBadSig() throws Exception {
        DnssecClient client = new DnssecClient(new LruCache(1024));
        assertFalse(client.queryDnssec("_443._tcp.bad-sig.dane.dns-oarc.net", Record.TYPE.TLSA).isAuthenticData());
    }

    @IntegrationTest
    public static void testUniDueSigOk() throws IOException {
        DnssecClient client = new DnssecClient(new LruCache(1024));
        assertAuthentic(client.queryDnssec("sigok.verteiltesysteme.net", Record.TYPE.A));
    }

    @IntegrationTest(expected = DnssecValidationFailedException.class)
    public static void testUniDueSigFail() throws IOException {
        DnssecClient client = new DnssecClient(new LruCache(1024));
        client.query("sigfail.verteiltesysteme.net", Record.TYPE.A);
    }

    @IntegrationTest
    public static void testCloudFlare() throws IOException {
        DnssecClient client = new DnssecClient(new LruCache(1024));
        assertAuthentic(client.queryDnssec("www.cloudflare-dnssec-auth.com", Record.TYPE.A));
    }

    private static void assertAuthentic(DnssecQueryResult dnssecMessage) {
        if (dnssecMessage.isAuthenticData()) return;

        StringBuilder sb = new StringBuilder();
        sb.append("Answer should contain authentic data while it does not. Reasons:\n");
        for (Iterator<DnssecUnverifiedReason> it = dnssecMessage.getUnverifiedReasons().iterator(); it.hasNext(); ) {
            DnssecUnverifiedReason unverifiedReason = it.next();
            sb.append(unverifiedReason);
            if (it.hasNext()) sb.append('\n');
        }
        throw new AssertionError(sb.toString());
    }
}
