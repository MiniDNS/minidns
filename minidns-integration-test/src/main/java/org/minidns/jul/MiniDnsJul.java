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
package org.minidns.jul;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

@SuppressWarnings("DateFormatConstant")
public class MiniDnsJul {

    private static final Logger LOGGER = Logger.getLogger(MiniDnsJul.class.getName());

    private static final InputStream LOG_MANAGER_CONFIG = new ByteArrayInputStream((
// @formatter:off
"org.minidns.level=FINEST" + '\n'
).getBytes(StandardCharsets.UTF_8)
);
// @formatter:on

    private static final DateTimeFormatter LONG_LOG_TIME_FORMAT = DateTimeFormatter.ofPattern("hh:mm:ss.SSS");

    private static final DateTimeFormatter SHORT_LOG_TIME_FORMAT = DateTimeFormatter.ofPattern("mm:ss.SSS");

    private static final Handler CONSOLE_HANDLER = new ConsoleHandler();

    private static boolean shortLog = true;

    static {
        try {
            LogManager.getLogManager().readConfiguration(LOG_MANAGER_CONFIG);
        } catch (SecurityException | IOException e) {
            LOGGER.log(Level.SEVERE, "Could not apply MiniDNS JUL configuration", e);
        }

        CONSOLE_HANDLER.setLevel(Level.OFF);
        CONSOLE_HANDLER.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord logRecord) {
                StringBuilder sb = new StringBuilder(256);

                Instant date = Instant.ofEpochMilli(logRecord.getMillis());
                String dateString;
                if (shortLog) {
					dateString = SHORT_LOG_TIME_FORMAT.format(date);
                } else {
					dateString = LONG_LOG_TIME_FORMAT.format(date);
                }
                sb.append(dateString).append(' ');

                String level = logRecord.getLevel().toString();
                if (shortLog) {
                    level = level.substring(0, 1);
                }
                sb.append(level).append(' ');

                String loggerName = logRecord.getLoggerName();
                if (shortLog) {
                    String[] parts = loggerName.split("\\.");
                    loggerName = parts[parts.length > 1 ? parts.length - 1 : 0];
                }
                sb.append(loggerName);
                sb.append(' ').append(logRecord.getSourceMethodName());

                if (shortLog) {
                    sb.append(' ');
                } else {
                    sb.append('\n');
                }

                sb.append(formatMessage(logRecord));
                if (logRecord.getThrown() != null) {
                    StringWriter sw = new StringWriter();
                    PrintWriter pw = new PrintWriter(sw);
                    // CHECKSTYLE:OFF
                    pw.println();
                    logRecord.getThrown().printStackTrace(pw);
                    // CHECKSTYLE:ON
                    pw.close();
                    sb.append(sw);
                }
                sb.append('\n');
                return sb.toString();
            }
        });
        Logger.getLogger("org.minidns").addHandler(CONSOLE_HANDLER);
    }

    public static void enableMiniDnsTrace() {
        enableMiniDnsTrace(true);
    }

    public static void enableMiniDnsTrace(boolean shortLog) {
        MiniDnsJul.shortLog = shortLog;
        CONSOLE_HANDLER.setLevel(Level.FINEST);
    }

    public static void disableMiniDnsTrace() {
        CONSOLE_HANDLER.setLevel(Level.OFF);
    }
}
