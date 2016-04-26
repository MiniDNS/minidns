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
package de.measite.minidns.integrationtest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Set;

import de.measite.minidns.hla.ResolverApi;
import de.measite.minidns.hla.ResolverResult;
import de.measite.minidns.record.A;

public class HlaTest {

    @IntegrationTest
    public static void resolverTest() throws IOException {
        ResolverResult<A> res = ResolverApi.NON_DNSSEC.resolve("geekplace.eu", A.class);
        assertEquals(true, res.wasSuccessful());
        Set<A> answers = res.getAnswers();
        assertEquals(1, answers.size());
        assertArrayEquals(new A(37, 221, 197, 223).toByteArray(), answers.iterator().next().toByteArray());
    }

}
