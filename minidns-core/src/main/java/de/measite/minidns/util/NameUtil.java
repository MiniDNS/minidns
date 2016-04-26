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
package de.measite.minidns.util;

import de.measite.minidns.DNSName;

/**
 * Utilities related to internationalized domain names and dns name handling.
 */
public final class NameUtil {

    /**
     * Check if two internationalized domain names are equal, possibly causing
     * a serialization of both domain names.
     *
     * @param name1 The first domain name.
     * @param name2 The second domain name.
     * @return True if both domain names are the same.
     */
    public static boolean idnEquals(String name1, String name2) {
        if (name1 == name2) return true; // catches null, null
        if (name1 == null) return false;
        if (name2 == null) return false;
        if (name1.equals(name2)) return true;

        return DNSName.from(name1).compareTo(DNSName.from(name2)) == 0;
    }

}
