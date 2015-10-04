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

public class Base32Test {
    @Test
    public void testEncodeToString() {
        assertEquals("", Base32.encodeToString(new byte[]{}));
        assertEquals("0410====", Base32.encodeToString(new byte[]{1, 2}));
        assertEquals("891K8HA6", Base32.encodeToString(new byte[]{0x42, 0x43, 0x44, 0x45, 0x46}));
        assertEquals("VS0FU07V03VG0===", Base32.encodeToString(new byte[]{-1, 0, -1, 0, -1, 0, -1, 0}));
    }
}
