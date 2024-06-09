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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.minidns.dnsname.DnsName;
import org.minidns.dnssec.DnssecClient;
import org.minidns.dnssec.DnssecQueryResult;
import org.minidns.integrationtest.IntegrationTestTools.CacheConfig;
import org.minidns.iterative.ReliableDnsClient.Mode;
import org.minidns.record.Record.TYPE;
import org.minidns.source.NetworkDataSourceWithAccounting;

public class IterativeDnssecTest {

    private static final DnsName DNSSEC_DOMAIN = IntegrationTestHelper.DNSSEC_DOMAIN;
    private static final TYPE RR_TYPE = IntegrationTestHelper.RR_TYPE;

    @IntegrationTest
    public static void shouldRequireLessQueries() throws IOException {
        DnssecClient normalCacheClient = getClient(CacheConfig.normal);
        DnssecQueryResult normalCacheResult = normalCacheClient.queryDnssec(DNSSEC_DOMAIN, RR_TYPE);
        assertTrue(normalCacheResult.isAuthenticData());
        NetworkDataSourceWithAccounting normalCacheNdswa = NetworkDataSourceWithAccounting.from(normalCacheClient);

        DnssecClient extendedCacheClient = getClient(CacheConfig.extended);
        DnssecQueryResult extendedCacheResult = extendedCacheClient.queryDnssec(DNSSEC_DOMAIN, RR_TYPE);
        assertTrue(extendedCacheResult.isAuthenticData());
        NetworkDataSourceWithAccounting extendedCacheNdswa = NetworkDataSourceWithAccounting.from(extendedCacheClient);

        final int normalCacheSuccessfulQueries = normalCacheNdswa.getStats().successfulQueries;
        final int extendedCacheSuccessfulQueries = extendedCacheNdswa.getStats().successfulQueries;
        assertTrue(
                normalCacheSuccessfulQueries > extendedCacheSuccessfulQueries,
                "Extend cache successful query count " + extendedCacheSuccessfulQueries
                + " is not less than normal cache successful query count " + normalCacheSuccessfulQueries);
    }

    private static DnssecClient getClient(CacheConfig cacheConfig) {
        DnssecClient client = IntegrationTestTools.getClient(cacheConfig);
        client.setMode(Mode.iterativeOnly);
        return client;
    }
}
