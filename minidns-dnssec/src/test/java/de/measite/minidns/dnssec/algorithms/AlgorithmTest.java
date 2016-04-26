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
package de.measite.minidns.dnssec.algorithms;

import org.junit.Before;

public class AlgorithmTest {
    protected AlgorithmMap algorithmMap;

    @Before
    public void setUp() throws Exception {
        algorithmMap = AlgorithmMap.INSTANCE;
    }
}
