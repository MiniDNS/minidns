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

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class Base64Test {
    @Test
    public void testEncodeToString() {
        assertEquals("", Base64.encodeToString(new byte[]{}));
        assertEquals("Qg==", Base64.encodeToString(new byte[]{0x42}));
        assertEquals("AQID", Base64.encodeToString(new byte[]{1, 2, 3}));
        assertEquals("CAIGAP8B/wA=", Base64.encodeToString(new byte[]{8, 2, 6, 0, -1, 1, -1, 0}));
    }
}
