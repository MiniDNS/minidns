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

import org.minidns.DnsCache;
import org.minidns.cache.ExtendedLruCache;
import org.minidns.cache.FullLruCache;
import org.minidns.cache.LruCache;
import org.minidns.dnssec.DnssecClient;
import org.minidns.source.NetworkDataSourceWithAccounting;

public class IntegrationTestTools {

    public enum CacheConfig {
        without,
        normal,
        extended,
        full,
    }

    public static DnssecClient getClient(CacheConfig cacheConfig) {
        DnsCache cache;
        switch (cacheConfig) {
        case without:
            cache = null;
            break;
        case normal:
            cache = new LruCache();
            break;
        case extended:
            cache = new ExtendedLruCache();
            break;
        case full:
            cache = new FullLruCache();
            break;
        default:
            throw new IllegalStateException();
        }

        DnssecClient client = new DnssecClient(cache);
        client.setDataSource(new NetworkDataSourceWithAccounting());
        return client;
    }

}
