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

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class NameUtilTest {

    @Test
    public void idnEqualsTest() {
        assertTrue(NameUtil.idnEquals(null, null));
        assertTrue(NameUtil.idnEquals("domain.example", "domain.example"));
        assertTrue(NameUtil.idnEquals("dömäin.example", "xn--dmin-moa0i.example"));
        assertTrue(NameUtil.idnEquals("موقع.وزارة-الاتصالات.مصر", "xn--4gbrim.xn----ymcbaaajlc6dj7bxne2c.xn--wgbh1c"));

        assertFalse(NameUtil.idnEquals("dömäin.example", null));
        assertFalse(NameUtil.idnEquals(null, "domain.example"));
        assertFalse(NameUtil.idnEquals("dömäin.example", "domain.example"));
        assertFalse(NameUtil.idnEquals("", "domain.example"));
    }

}
