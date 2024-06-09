/*
 * Copyright 2015-2024 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.integrationtest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Set;

import org.minidns.hla.ResolverApi;
import org.minidns.hla.ResolverResult;
import org.minidns.hla.SrvResolverResult;
import org.minidns.record.A;
import org.minidns.record.SRV;

public class HlaTest {

    @IntegrationTest
    public static void resolverTest() throws IOException {
        ResolverResult<A> res = ResolverApi.INSTANCE.resolve("geekplace.eu", A.class);
        assertEquals(true, res.wasSuccessful());
        Set<A> answers = res.getAnswers();
        assertEquals(1, answers.size());
        assertArrayEquals(new A(5, 45, 100, 158).toByteArray(), answers.iterator().next().toByteArray());
    }

    @IntegrationTest
    public static void idnSrvTest() throws IOException {
        ResolverResult<SRV> res = ResolverApi.INSTANCE.resolve("_xmpp-client._tcp.im.plä.net", SRV.class);
        Set<SRV> answers = res.getAnswers();
        assertEquals(1, answers.size());

        SRV srv = answers.iterator().next();

        ResolverResult<A> aRes = ResolverApi.INSTANCE.resolve(srv.target, A.class);

        assertTrue(aRes.wasSuccessful());
    }

    @IntegrationTest
    public static void resolveSrvTest() throws IOException {
        SrvResolverResult resolverResult = ResolverApi.INSTANCE.resolveSrv("_xmpp-client._tcp.jabber.org");
        Set<SRV> answers = resolverResult.getAnswers();
        assertFalse(answers.isEmpty());
    }
}
