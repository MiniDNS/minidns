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

import static java.lang.System.out;

import java.io.IOException;
import java.util.Arrays;

import org.minidns.AbstractDnsClient;
import org.minidns.DnsCache;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.dnssec.DnssecClient;
import org.minidns.integrationtest.IntegrationTestTools;
import org.minidns.integrationtest.IntegrationTestTools.CacheConfig;
import org.minidns.record.Record.TYPE;
import org.minidns.source.NetworkDataSourceWithAccounting;

public class MiniDnsStats {

    public static void main(String[] args) throws IOException {
        showDnssecStats();
    }

    public static void showDnssecStats() throws IOException {
        showDnssecStats("siccegge.de", TYPE.A);
    }

    public static void showDnssecStats(String name, TYPE type) throws IOException {
        DnssecClient client;

        client = getClient(CacheConfig.without);
        // CHECKSTYLE:OFF
        out.println(gatherStatsFor(client, "Without Cache", name, type));
        // CHECKSTYLE:ON

        client = getClient(CacheConfig.normal);
        // CHECKSTYLE:OFF
        out.println(gatherStatsFor(client, "With Cache", name, type));
        // CHECKSTYLE:ON

        client = getClient(CacheConfig.extended);
        // CHECKSTYLE:OFF
        out.println(gatherStatsFor(client, "With Extended Cache", name, type));
        // CHECKSTYLE:ON

        client = getClient(CacheConfig.full);
        // CHECKSTYLE:OFF
        out.println(gatherStatsFor(client, "With Full Cache", name, type));
        // CHECKSTYLE:ON
    }

    public static StringBuilder gatherStatsFor(DnssecClient client, String testName, String name, TYPE type) throws IOException {
        DnsQueryResult result;
        long start, stop;

        start = System.currentTimeMillis();
        result = client.query(name, type);
        stop = System.currentTimeMillis();

        StringBuilder sb = new StringBuilder();
        sb.append(testName).append('\n');
        char[] headline = new char[testName.length()];
        Arrays.fill(headline, '#');
        sb.append(headline).append('\n');
        sb.append(result).append('\n');
        sb.append("Took ").append(stop - start).append("ms").append('\n');
        sb.append(getStats(client)).append('\n');
        sb.append('\n');

        return sb;
    }

    public static DnssecClient getClient(CacheConfig cacheConfig) {
        return IntegrationTestTools.getClient(cacheConfig);
    }

    public static StringBuilder getStats(AbstractDnsClient client) {
        StringBuilder sb = new StringBuilder();

        NetworkDataSourceWithAccounting ndswa = NetworkDataSourceWithAccounting.from(client);
        if (ndswa != null) {
            sb.append(ndswa.getStats().toString());
        } else {
            sb.append("Client is not using " + NetworkDataSourceWithAccounting.class.getSimpleName());
        }

        DnsCache dnsCache = client.getCache();
        if (dnsCache != null) {
            sb.append(dnsCache);
        } else {
            sb.append("Client is not using a Cache");
        }

        return sb;
    }
}
