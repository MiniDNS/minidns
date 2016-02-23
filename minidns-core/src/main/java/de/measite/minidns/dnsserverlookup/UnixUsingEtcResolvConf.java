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
package de.measite.minidns.dnsserverlookup;

import de.measite.minidns.util.PlatformDetection;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class UnixUsingEtcResolvConf extends AbstractDNSServerLookupMechanism {

    public static final DNSServerLookupMechanism INSTANCE = new UnixUsingEtcResolvConf();
    public static final int PRIORITY = 2000;

    private static final String RESOLV_CONF_FILE = "/etc/resolv.conf";
    private static final String NAMESERVER_PREFIX = "nameserver ";

    protected UnixUsingEtcResolvConf() {
        super(UnixUsingEtcResolvConf.class.getSimpleName(), PRIORITY);
    }

    @Override
    public String[] getDnsServerAddresses() {
        if (PlatformDetection.isAndroid()) {
            // Don't rely on resolv.conf when on Android
            return null;
        }

        File file = new File(RESOLV_CONF_FILE);
        if (!file.exists()) {
            // Not very unixoid systems
            return null;
        }

        List<String> servers = new ArrayList<>();
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(NAMESERVER_PREFIX)) {
                    servers.add(line.substring(NAMESERVER_PREFIX.length()));
                }
            }
        } catch (IOException e) {
            return null;
        } finally {
            if (reader != null) try {
                reader.close();
            } catch (IOException ignored) {
                // continue
            }
        }

        if (servers.isEmpty()) {
            return null;
        }
        return servers.toArray(new String[servers.size()]);
    }
}
