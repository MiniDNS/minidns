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

import de.measite.minidns.DNSCache;
import de.measite.minidns.cache.ExtendedLRUCache;
import de.measite.minidns.cache.FullLRUCache;
import de.measite.minidns.cache.LRUCache;
import de.measite.minidns.dnssec.DNSSECClient;
import de.measite.minidns.source.NetworkDataSourceWithAccounting;

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
            cache = new LRUCache(1024);
            break;
        case extended:
            cache = new ExtendedLRUCache(1024);
            break;
        case full:
            cache = new FullLRUCache(1024);
            break;
        default:
            throw new IllegalStateException();
        }

        DNSSECClient client = new DNSSECClient(cache);
        client.setDataSource(new NetworkDataSourceWithAccounting());
        return client;
    }

}
