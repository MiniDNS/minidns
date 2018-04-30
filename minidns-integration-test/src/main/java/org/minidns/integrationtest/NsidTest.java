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

import org.minidns.DnsClient;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsmessage.DnsMessage.Builder;
import org.minidns.edns.Nsid;
import org.minidns.edns.Edns.OptionCode;
import org.minidns.iterative.IterativeDnsClient;
import org.minidns.record.Record.TYPE;

import static org.junit.Assert.assertNotNull;

public class NsidTest {

    @IntegrationTest
    public static Nsid testNsidLRoot() {
        DnsClient client = new DnsClient(null) {
            @Override
            protected Builder newQuestion(Builder message) {
                message.getEdnsBuilder().addEdnsOption(Nsid.REQUEST);
                return super.newQuestion(message);
            }
        };
        DnsMessage response = null;
        Question q = new Question("de", TYPE.NS);
        for (InetAddress lRoot : IterativeDnsClient.getRootServer('l')) {
            try {
                response = client.query(q, lRoot);
            } catch (IOException e) {
                continue;
            }
            break;
        }
        Nsid nsid = response.getEdns().getEdnsOption(OptionCode.NSID);
        assertNotNull(nsid);
        return nsid;
    }
}
