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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

/**
 * Try to retrieve the list of DNS server by calling SystemProperties.
 */
public class AndroidUsingReflection extends AbstractDnsServerLookupMechanism {

    public static final DnsServerLookupMechanism INSTANCE = new AndroidUsingReflection();
    public static final int PRIORITY = 1000;

    private final Method systemPropertiesGet;

    protected AndroidUsingReflection() {
        super(AndroidUsingReflection.class.getSimpleName(), PRIORITY);
        Method systemPropertiesGet = null;
        if (PlatformDetection.isAndroid()) {
            try {
                Class<?> SystemProperties = Class.forName("android.os.SystemProperties");
                systemPropertiesGet = SystemProperties.getMethod("get", new Class<?>[] { String.class });
            } catch (ClassNotFoundException | NoSuchMethodException | SecurityException e) {
                // This is not unexpected, as newer Android versions do not provide access to it any more.
                LOGGER.log(Level.FINE, "Can not get method handle for android.os.SystemProperties.get(String).", e);
            }
        }
        this.systemPropertiesGet = systemPropertiesGet;
    }

    @Override
    public List<String> getDnsServerAddresses() {
        ArrayList<String> servers = new ArrayList<String>(5);

        for (String propKey : new String[] {
                "net.dns1", "net.dns2", "net.dns3", "net.dns4"}) {

            String value;
            try {
                value = (String) systemPropertiesGet.invoke(null, propKey);
            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                LOGGER.log(Level.WARNING, "Exception in findDNSByReflection", e);
                return null;
            }

            if (value == null) continue;
            if (value.length() == 0) continue;
            if (servers.contains(value)) continue;

            InetAddress ip;
            try {
                ip = InetAddress.getByName(value);
            } catch (UnknownHostException e) {
                LOGGER.log(Level.WARNING, "Exception in findDNSByReflection", e);
                continue;
            }

            if (ip == null) continue;

            value = ip.getHostAddress();

            if (value == null) continue;
            if (value.length() == 0) continue;
            if (servers.contains(value)) continue;

            servers.add(value);
        }

        if (servers.size() > 0) {
            return servers;
        }

        return null;
    }

    @Override
    public boolean isAvailable() {
        return systemPropertiesGet != null;
    }

}
