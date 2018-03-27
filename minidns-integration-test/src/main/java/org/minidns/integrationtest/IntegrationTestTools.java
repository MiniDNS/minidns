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

import org.minidns.DNSCache;
import org.minidns.cache.ExtendedLRUCache;
import org.minidns.cache.FullLRUCache;
import org.minidns.cache.LRUCache;
import org.minidns.dnssec.DNSSECClient;
import org.minidns.source.NetworkDataSourceWithAccounting;

public class IntegrationTestTools {

    public enum CacheConfig {
        without,
        normal,
        extended,
        full,
    }

    public static DNSSECClient getClient(CacheConfig cacheConfig) {
        DNSCache cache;
        switch (cacheConfig) {
        case without:
            cache = null;
            break;
        case normal:
            cache = new LRUCache();
            break;
        case extended:
            cache = new ExtendedLRUCache();
            break;
        case full:
            cache = new FullLRUCache();
            break;
        default:
            throw new IllegalStateException();
        }

        DNSSECClient client = new DNSSECClient(cache);
        client.setDataSource(new NetworkDataSourceWithAccounting());
        return client;
    }

}
