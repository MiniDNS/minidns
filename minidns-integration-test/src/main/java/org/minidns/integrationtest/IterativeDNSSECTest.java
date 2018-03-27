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
package org.minidns.integrationtest;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.minidns.DNSName;
import org.minidns.dnssec.DNSSECClient;
import org.minidns.dnssec.DNSSECMessage;
import org.minidns.integrationtest.IntegrationTestTools.CacheConfig;
import org.minidns.iterative.ReliableDNSClient.Mode;
import org.minidns.record.Record.TYPE;
import org.minidns.source.NetworkDataSourceWithAccounting;

public class IterativeDNSSECTest {

    private static final DNSName DNSSEC_DOMAIN = IntegrationTestHelper.DNSSEC_DOMAIN;
    private static final TYPE RR_TYPE = IntegrationTestHelper.RR_TYPE;

    @IntegrationTest
    public static void shouldRequireLessQueries() throws IOException {
        DNSSECClient normalCacheClient = getClient(CacheConfig.normal);
        DNSSECMessage normalCacheResult = normalCacheClient.queryDnssec(DNSSEC_DOMAIN, RR_TYPE);
        assertTrue(normalCacheResult.authenticData);
        NetworkDataSourceWithAccounting normalCacheNdswa = NetworkDataSourceWithAccounting.from(normalCacheClient);

        DNSSECClient extendedCacheClient = getClient(CacheConfig.extended);
        DNSSECMessage extendedCacheResult = extendedCacheClient.queryDnssec(DNSSEC_DOMAIN, RR_TYPE);
        assertTrue(extendedCacheResult.authenticData);
        NetworkDataSourceWithAccounting extendedCacheNdswa = NetworkDataSourceWithAccounting.from(extendedCacheClient);

        assertTrue(normalCacheNdswa.getStats().successfulQueries > extendedCacheNdswa.getStats().successfulQueries);
    }

    private static DNSSECClient getClient(CacheConfig cacheConfig) {
        DNSSECClient client = IntegrationTestTools.getClient(cacheConfig);
        client.setMode(Mode.iterativeOnly);
        return client;
    }
}
