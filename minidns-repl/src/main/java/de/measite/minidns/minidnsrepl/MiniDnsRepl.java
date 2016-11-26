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
package de.measite.minidns.minidnsrepl;

import java.io.IOException;
import java.lang.reflect.Field;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSClient;
import de.measite.minidns.cache.LRUCache;
import de.measite.minidns.dnssec.DNSSECClient;
import de.measite.minidns.jul.MiniDnsJul;
import de.measite.minidns.recursive.RecursiveDNSClient;

public class MiniDnsRepl {

    public static final DNSClient DNSCLIENT = new DNSClient();
    public static final RecursiveDNSClient RECURSIVEDNSCLIENT = new RecursiveDNSClient();
    public static final DNSSECClient DNSSECCLIENT = new DNSSECClient();

    static {
        LRUCache cache = null;
        try {
            Field defaultCacheField = AbstractDNSClient.class.getDeclaredField("DEFAULT_CACHE");
            defaultCacheField.setAccessible(true);
            cache = (LRUCache) defaultCacheField.get(null);
        } catch (IllegalAccessException | NoSuchFieldException | SecurityException e) {
            throw new IllegalStateException(e);
        }
        DEFAULT_CACHE = cache;
    }

    public static final LRUCache DEFAULT_CACHE;

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
        DNSSECStats.iterativeDnssecLookupNormalVsExtendedCache();
        /*
        DNSSECClient client = new DNSSECClient(new LRUCache(1024));
        DNSSECMessage secRes = client.queryDnssec("verteiltesysteme.net", TYPE.A);
        */

        /*
        DNSSECStats.iterativeDnssecLookupNormalVsExtendedCache();
        NSID nsid = NSIDTest.testNsidLRoot();
        DNSMessage res = RECURSIVEDNSCLIENT.query("mate.geekplace.eu", TYPE.A);
        */
        // CHECKSTYLE:OFF
//        System.out.println(nsid);
//      System.out.println(secRes);
//        System.out.println(res);
        // CHCECKSTYLE:ON
    }

}
