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

import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;

import org.minidns.AbstractDnsClient;
import org.minidns.DnsClient;
import org.minidns.cache.LruCache;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnssec.DnssecClient;
import org.minidns.hla.DnssecResolverApi;
import org.minidns.hla.ResolverResult;
import org.minidns.iterative.IterativeDnsClient;
import org.minidns.jul.MiniDnsJul;
import org.minidns.record.A;

public class MiniDnsRepl {

    public static final DnsClient DNSCLIENT = new DnsClient();
    public static final IterativeDnsClient ITERATIVEDNSCLIENT = new IterativeDnsClient();
    public static final DnssecClient DNSSECCLIENT = new DnssecClient();

    static {
        LruCache cache = null;
        try {
            Field defaultCacheField = AbstractDnsClient.class.getDeclaredField("DEFAULT_CACHE");
            defaultCacheField.setAccessible(true);
            cache = (LruCache) defaultCacheField.get(null);
        } catch (IllegalAccessException | NoSuchFieldException | SecurityException e) {
            throw new IllegalStateException(e);
        }
        DEFAULT_CACHE = cache;
    }

    public static final LruCache DEFAULT_CACHE;

    public static void init() {
        // CHECKSTYLE:OFF
        System.out.println("MiniDNS REPL");
        // CHECKSTYLE:ON
    }

    public static void clearCache() throws SecurityException, IllegalArgumentException {
        DEFAULT_CACHE.clear();
    }

    public static void main(String[] args) throws IOException, SecurityException, IllegalArgumentException {
        MiniDnsJul.enableMiniDnsTrace();

        ResolverResult<A> res = DnssecResolverApi.INSTANCE.resolveDnssecReliable("verteiltesysteme.net", A.class);
        /*
        DnssecStats.iterativeDnssecLookupNormalVsExtendedCache();
        DnssecClient client = new DNSSECClient(new LRUCache(1024));
        DnssecMessage secRes = client.queryDnssec("verteiltesysteme.net", TYPE.A);
        */

        /*
        DnssecStats.iterativeDnssecLookupNormalVsExtendedCache();
        Nsid nsid = NSIDTest.testNsidLRoot();
        DnsMessage res = RECURSIVEDNSCLIENT.query("mate.geekplace.eu", TYPE.A);
        */
        // CHECKSTYLE:OFF
        System.out.println(res);
//        System.out.println(nsid);
//      System.out.println(secRes);
//        System.out.println(res);
        // CHCECKSTYLE:ON
    }

    public static void writeToFile(DnsMessage dnsMessage, String path) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            dnsMessage.writeTo(fos, true);
        }
    }
}
