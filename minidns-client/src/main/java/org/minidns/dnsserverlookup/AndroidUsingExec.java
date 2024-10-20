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
package org.minidns.dnsserverlookup;

import org.minidns.util.PlatformDetection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

/**
 * Try to retrieve the list of DNS server by executing getprop.
 */
public final class AndroidUsingExec extends AbstractDnsServerLookupMechanism {

    public static final DnsServerLookupMechanism INSTANCE = new AndroidUsingExec();
    public static final int PRIORITY = AndroidUsingReflection.PRIORITY - 1;

    private AndroidUsingExec() {
        super(AndroidUsingExec.class.getSimpleName(), PRIORITY);
    }

    @Override
    public List<String> getDnsServerAddresses() {
        try {
            Process process = Runtime.getRuntime().exec("getprop");
            InputStream inputStream = process.getInputStream();
            LineNumberReader lnr = new LineNumberReader(
                new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            Set<String> server = parseProps(lnr, true);
            if (server.size() > 0) {
                List<String> res = new ArrayList<>(server.size());
                res.addAll(server);
                return res;
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Exception in findDNSByExec", e);
        }
        return null;
    }

    @Override
    public boolean isAvailable() {
        return PlatformDetection.isAndroid();
    }

    private static final String PROP_DELIM = "]: [";
    static Set<String> parseProps(BufferedReader lnr, boolean logWarning) throws UnknownHostException, IOException {
        String line = null;
        Set<String> server = new HashSet<String>(6);

        while ((line = lnr.readLine()) != null) {
            int split = line.indexOf(PROP_DELIM);
            if (split == -1) {
                continue;
            }
            String property = line.substring(1, split);

            int valueStart = split + PROP_DELIM.length();
            int valueEnd = line.length() - 1;
            if (valueEnd < valueStart) {
                // This can happen if a newline sneaks in as the first character of the property value. For example
                // "[propName]: [\n…]".
                if (logWarning) {
                    LOGGER.warning("Malformed property detected: \"" + line + '"');
                }
                continue;
            }

            String value = line.substring(valueStart, valueEnd);

            if (value.isEmpty()) {
                continue;
            }

            if (property.endsWith(".dns") || property.endsWith(".dns1") ||
                property.endsWith(".dns2") || property.endsWith(".dns3") ||
                property.endsWith(".dns4")) {

                // normalize the address

                InetAddress ip = InetAddress.getByName(value);

                if (ip == null) continue;

                value = ip.getHostAddress();

                if (value == null) continue;
                if (value.length() == 0) continue;

                server.add(value);
            }
        }

        return server;
    }
}
