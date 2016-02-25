/*
 * Copyright 2015 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.minidnsrepl;

import java.lang.reflect.Field;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSClient;
import de.measite.minidns.LRUCache;
import de.measite.minidns.dnssec.DNSSECClient;

public class MiniDnsRepl {

    public static final DNSClient DNSCLIENT = new DNSClient();
    public static final DNSSECClient DNSSECCLIENT = new DNSSECClient();


    public static void init() {
        // CHECKSTYLE:OFF
        System.out.println("MiniDNS REPL");
        // CHECKSTYLE:ON
    }

    public static void clearCache() throws NoSuchFieldException, SecurityException, IllegalArgumentException,
            IllegalAccessException {
        Field defaultCacheField = AbstractDNSClient.class.getDeclaredField("DEFAULT_CACHE");
        defaultCacheField.setAccessible(true);
        LRUCache defaultCache = (LRUCache) defaultCacheField.get(null);
        defaultCache.clear();
    }
}
