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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

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

    private static final Logger MINIDNS_LOGGER = Logger.getLogger("de.measite.minidns");
    private static final InputStream LOG_MANAGER_CONFIG = new ByteArrayInputStream((
// @formatter:off
"de.measite.minidns.level=FINEST" + '\n'
).getBytes()
);
// @formatter:on
    private static final SimpleDateFormat LOG_TIME_FORMAT = new SimpleDateFormat("hh:mm:ss.SSS");

    public static void traceMinidns() throws SecurityException, IOException {
        LogManager.getLogManager().readConfiguration(LOG_MANAGER_CONFIG);
        Handler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.FINEST);
        consoleHandler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord logRecord) {
                StringBuffer sb = new StringBuffer(256);
                Date date = new Date(logRecord.getMillis());
                String dateString;
                synchronized (LOG_TIME_FORMAT) {
                    dateString = LOG_TIME_FORMAT.format(date);
                }
                sb.append(dateString).append(' ').append(logRecord.getLoggerName()).append(' ').append(logRecord.getSourceMethodName()).append('\n');
                sb.append(logRecord.getLevel()).append(' ').append(logRecord.getMessage()).append('\n');
                return sb.toString();
            }
        });
        MINIDNS_LOGGER.addHandler(consoleHandler);
    }
}
