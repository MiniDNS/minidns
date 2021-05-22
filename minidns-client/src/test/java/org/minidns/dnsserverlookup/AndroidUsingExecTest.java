/*
 * Copyright 2015-2021 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.dnsserverlookup;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.net.UnknownHostException;
import java.util.Set;

import org.junit.jupiter.api.Test;

public class AndroidUsingExecTest {

    private static final String PROPS_WITH_NEWLINE = "[property.name]: [\n" +
            "]\n";

    @Test
    public void parsePropsWithNewlineTest() throws UnknownHostException, IOException {
        Reader reader = new StringReader(PROPS_WITH_NEWLINE);
        BufferedReader bufferedReader = new BufferedReader(reader);

        Set<String> servers = AndroidUsingExec.parseProps(bufferedReader, false);

        assertTrue(servers.isEmpty());
    }
}
