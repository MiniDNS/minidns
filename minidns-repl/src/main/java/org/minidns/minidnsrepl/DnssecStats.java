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
package org.minidns.minidnsrepl;

import java.io.IOException;

import org.minidns.cache.ExtendedLruCache;
import org.minidns.dnsname.DnsName;
import org.minidns.dnssec.DnssecClient;
import org.minidns.dnssec.DnssecQueryResult;
import org.minidns.dnssec.DnssecUnverifiedReason;
import org.minidns.integrationtest.IntegrationTestTools.CacheConfig;
import org.minidns.iterative.ReliableDnsClient.Mode;
import org.minidns.jul.MiniDnsJul;
import org.minidns.record.Record.TYPE;

public class DnssecStats {

    private static final DnsName DOMAIN = DnsName.from("verteiltesysteme.net");
    private static final TYPE RR_TYPE = TYPE.A;

    public static void iterativeDnssecLookupNormalVsExtendedCache() throws IOException {
        // iterativeDnssecLookup(CacheConfig.normal);
        iterativeDnssecLookup(CacheConfig.extended);
    }

    private static void iterativeDnssecLookup(CacheConfig cacheConfig) throws IOException {
        DnssecClient client = MiniDnsStats.getClient(cacheConfig);
        client.setMode(Mode.iterativeOnly);
        DnssecQueryResult secRes = client.queryDnssec(DOMAIN, RR_TYPE);

        StringBuilder stats = MiniDnsStats.getStats(client);
        stats.append('\n');
        stats.append(secRes);
        stats.append('\n');
        for (DnssecUnverifiedReason r : secRes.getUnverifiedReasons()) {
            stats.append(r);
        }
        stats.append("\n\n");
        // CHECKSTYLE:OFF
        System.out.println(stats);
        // CHECKSTYLE:ON
    }

    public static void iterativeDnsssecTest() throws SecurityException, IllegalArgumentException, IOException {
        MiniDnsJul.enableMiniDnsTrace();
        DnssecClient client = new DnssecClient(new ExtendedLruCache());
        client.setMode(Mode.iterativeOnly);

        DnssecQueryResult secRes = client.queryDnssec("verteiltesysteme.net", TYPE.A);

        // CHECKSTYLE:OFF
        System.out.println(secRes);
        // CHECKSTYLE:ON
    }

}
