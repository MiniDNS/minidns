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
package org.minidns.integrationtest;

import java.io.IOException;
import java.net.InetAddress;

import org.minidns.DNSClient;
import org.minidns.dnsmessage.DNSMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsmessage.DNSMessage.Builder;
import org.minidns.edns.NSID;
import org.minidns.edns.EDNS.OptionCode;
import org.minidns.iterative.IterativeDNSClient;
import org.minidns.record.Record.TYPE;

import static org.junit.Assert.assertNotNull;

public class NSIDTest {

    @IntegrationTest
    public static NSID testNsidLRoot() {
        DNSClient client = new DNSClient(null) {
            @Override
            protected Builder newQuestion(Builder message) {
                message.getEdnsBuilder().addEdnsOption(NSID.REQUEST);
                return super.newQuestion(message);
            }
        };
        DNSMessage response = null;
        Question q = new Question("de", TYPE.NS);
        for (InetAddress lRoot : IterativeDNSClient.getRootServer('l')) {
            try {
                response = client.query(q, lRoot);
            } catch (IOException e) {
                continue;
            }
            break;
        }
        NSID nsid = response.getEdns().getEdnsOption(OptionCode.NSID);
        assertNotNull(nsid);
        return nsid;
    }
}
