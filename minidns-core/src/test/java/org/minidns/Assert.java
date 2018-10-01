/*
 * Copyright 2015-2018 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

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

    public static <T> void assertArrayContentEquals(T[] expect, Collection<? extends T> value) {
        assertEquals(expect.length, value.size());
        List<T> list = new ArrayList<>(Arrays.asList(expect));
        for (Object type : value) {
            assertTrue(list.remove(type));
        }
        assertTrue(list.isEmpty());
    }
}
