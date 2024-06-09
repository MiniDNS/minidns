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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class UnixUsingEtcResolvConf extends AbstractDnsServerLookupMechanism {

    public static final DnsServerLookupMechanism INSTANCE = new UnixUsingEtcResolvConf();
    public static final int PRIORITY = 2000;

    private static final Logger LOGGER = Logger.getLogger(UnixUsingEtcResolvConf.class.getName());

    private static final String RESOLV_CONF_FILE = "/etc/resolv.conf";
    private static final Pattern NAMESERVER_PATTERN = Pattern.compile("^nameserver\\s+(.*)$");

    private static List<String> cached;
    private static long lastModified;

    private UnixUsingEtcResolvConf() {
        super(UnixUsingEtcResolvConf.class.getSimpleName(), PRIORITY);
    }

    @Override
    public List<String> getDnsServerAddresses() {
        File file = new File(RESOLV_CONF_FILE);
        if (!file.exists()) {
            // Not very unixoid systems
            return null;
        }

        long currentLastModified = file.lastModified();
        if (currentLastModified == lastModified && cached != null) {
            return cached;
        }

        List<String> servers = new ArrayList<>();
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher matcher = NAMESERVER_PATTERN.matcher(line);
                if (matcher.matches()) {
                    servers.add(matcher.group(1).trim());
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Could not read from " + RESOLV_CONF_FILE, e);
            return null;
        } finally {
            if (reader != null) try {
                reader.close();
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Could not close reader", e);
            }
        }

        if (servers.isEmpty()) {
            LOGGER.fine("Could not find any nameservers in " + RESOLV_CONF_FILE);
            return null;
        }

        cached = servers;
        lastModified = currentLastModified;

        return cached;
    }

    @Override
    public boolean isAvailable() {
        if (PlatformDetection.isAndroid()) {
            // Don't rely on resolv.conf when on Android
            return false;
        }

        File file = new File(RESOLV_CONF_FILE);

        boolean resolvConfFileExists;
        try {
            resolvConfFileExists = file.exists();
        } catch (SecurityException securityException) {
            LOGGER.log(Level.FINE, "Access to /etc/resolv.conf not possible", securityException);
            return false;
        }
        return resolvConfFileExists;
    }

}
