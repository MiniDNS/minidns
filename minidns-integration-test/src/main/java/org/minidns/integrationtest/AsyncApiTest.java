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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.minidns.DnsClient;
import org.minidns.record.Record;
import org.minidns.MiniDnsFuture;
import org.minidns.dnsmessage.DnsMessage.RESPONSE_CODE;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.source.AbstractDnsDataSource;
import org.minidns.source.AbstractDnsDataSource.QueryMode;
import org.minidns.source.async.AsyncNetworkDataSource;

public class AsyncApiTest {

    public static void main(String[] args) throws IOException {
        tcpAsyncApiTest();
    }

    public static void simpleAsyncApiTest() throws IOException {
        DnsClient client = new DnsClient();
        client.setDataSource(new AsyncNetworkDataSource());
        client.getDataSource().setTimeout(60 * 60 * 1000);

        MiniDnsFuture<DnsQueryResult, IOException> future = client.queryAsync("example.com", Record.TYPE.NS);
        DnsQueryResult result = future.getOrThrow();
        assertEquals(RESPONSE_CODE.NO_ERROR, result.response.responseCode);
    }

    public static void tcpAsyncApiTest() throws IOException {
        AbstractDnsDataSource dataSource = new AsyncNetworkDataSource();
        dataSource.setTimeout(60 * 60 * 1000);
        dataSource.setUdpPayloadSize(256);
        dataSource.setQueryMode(QueryMode.tcp);

        DnsClient client = new DnsClient();
        client.setDataSource(dataSource);
        client.setAskForDnssec(true);

        MiniDnsFuture<DnsQueryResult, IOException> future = client.queryAsync("google.com", Record.TYPE.AAAA);
        DnsQueryResult result = future.getOrThrow();
        assertEquals(RESPONSE_CODE.NO_ERROR, result.response.responseCode);
    }
}
