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
package de.measite.minidns.util;

public class PlatformDetection {

    private static Boolean android;

    public static boolean isAndroid() {
        if (android == null) {
            try {
                Class.forName("android.Manifest"); // throws execption when not on Android
                android = true;
            } catch (Exception e) {
                android = false;
            }
        }
        return android;
    }
}
