/*
 * Copyright 2015-2017 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.util;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

public class InetAddressUtil {

    public static Inet4Address ipv4From(CharSequence cs) {
        InetAddress inetAddress;
        try {
            inetAddress = InetAddress.getByName(cs.toString());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
        if (inetAddress instanceof Inet4Address) {
            return (Inet4Address) inetAddress;
        }
        throw new IllegalArgumentException();
    }

    public static Inet6Address ipv6From(CharSequence cs) {
        InetAddress inetAddress;
        try {
            inetAddress = InetAddress.getByName(cs.toString());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
        if (inetAddress instanceof Inet6Address) {
            return (Inet6Address) inetAddress;
        }
        throw new IllegalArgumentException();
    }

    // IPV4_REGEX from http://stackoverflow.com/a/46168/194894 by Kevin Wong (http://stackoverflow.com/users/4792/kevin-wong) licensed under
    // CC BY-SA 3.0.
    private final static Pattern IPV4_PATTERN = Pattern.compile("\\A(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}\\z");

    public static boolean isIpV4Address(CharSequence address) {
        if (address == null) {
            return false;
        }
        return IPV4_PATTERN.matcher(address).matches();
    }

    // IPv6 Regular Expression from http://stackoverflow.com/a/17871737/194894 by David M. Syzdek
    // (http://stackoverflow.com/users/903194/david-m-syzdek) licensed under CC BY-SA 3.0.
    private final static Pattern IPV6_PATTERN = Pattern.compile(
            "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))");

    public static boolean isIpV6Address(CharSequence address) {
        if (address == null) {
            return false;
        }
        return IPV6_PATTERN.matcher(address).matches();
    }

    public static boolean isIpAddress(CharSequence address) {
        return isIpV6Address(address) || isIpV4Address(address);
    }
}
