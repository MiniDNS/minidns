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
package de.measite.minidns;

import static org.junit.Assert.assertEquals;

public class Assert {

    public static void assertCsEquals(CharSequence expected, CharSequence actual) {
        assertCsEquals(null, expected, actual);
    }

    public static void assertCsEquals(String message, CharSequence expected, CharSequence actual) {
        if (expected != null && actual != null) {
            assertEquals(message, expected.toString(), actual.toString());
        } else {
            assertEquals(message, expected, actual);
        }
    }

}
