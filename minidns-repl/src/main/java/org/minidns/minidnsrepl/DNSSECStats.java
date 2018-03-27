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
package org.minidns.minidnsrepl;

import java.io.IOException;

import org.minidns.DNSName;
import org.minidns.Record.TYPE;
import org.minidns.cache.ExtendedLRUCache;
import org.minidns.dnssec.DNSSECClient;
import org.minidns.dnssec.DNSSECMessage;
import org.minidns.dnssec.UnverifiedReason;
import org.minidns.integrationtest.IntegrationTestTools.CacheConfig;
import org.minidns.iterative.ReliableDNSClient.Mode;
import org.minidns.jul.MiniDnsJul;

public class DNSSECStats {

    private static final DNSName DOMAIN = DNSName.from("verteiltesysteme.net");
    private static final TYPE RR_TYPE = TYPE.A;

    public static void iterativeDnssecLookupNormalVsExtendedCache() throws IOException {
        // iterativeDnssecLookup(CacheConfig.normal);
        iterativeDnssecLookup(CacheConfig.extended);
    }

    private static void iterativeDnssecLookup(CacheConfig cacheConfig) throws IOException {
        DNSSECClient client = MiniDNSStats.getClient(cacheConfig);
        client.setMode(Mode.iterativeOnly);
        DNSSECMessage secRes = client.queryDnssec(DOMAIN, RR_TYPE);

        StringBuilder stats = MiniDNSStats.getStats(client);
        stats.append('\n');
        stats.append(secRes);
        stats.append('\n');
        for (UnverifiedReason r : secRes.getUnverifiedReasons()) {
            stats.append(r);
        }
        stats.append("\n\n");
        // CHECKSTYLE:OFF
        System.out.println(stats);
        // CHECKSTYLE:ON
    }

    public static void iterativeDnsssecTest() throws SecurityException, IllegalArgumentException, IOException {
        MiniDnsJul.enableMiniDnsTrace();
        DNSSECClient client = new DNSSECClient(new ExtendedLRUCache());
        client.setMode(Mode.iterativeOnly);

        DNSSECMessage secRes = client.queryDnssec("verteiltesysteme.net", TYPE.A);

        // CHECKSTYLE:OFF
        System.out.println(secRes);
        // CHECKSTYLE:ON
    }

}
