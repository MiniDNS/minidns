/*
 * Copyright 2015-2017 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.integrationtest;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import de.measite.minidns.DNSClient;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.DNSMessage.RESPONSE_CODE;
import de.measite.minidns.MiniDnsFuture;
import de.measite.minidns.Record;
import de.measite.minidns.source.DNSDataSource;
import de.measite.minidns.source.DNSDataSource.QueryMode;
import de.measite.minidns.source.async.AsyncNetworkDataSource;

public class AsyncApiTest {

    public static void main(String[] args) throws IOException {
        tcpAsyncApiTest();
    }

    public static void simpleAsyncApiTest() throws IOException {
        DNSClient client = new DNSClient();
        client.setDataSource(new AsyncNetworkDataSource());
        client.getDataSource().setTimeout(60 * 60 * 1000);

        MiniDnsFuture<DNSMessage, IOException> future = client.queryAsync("example.com", Record.TYPE.NS);
        DNSMessage response = future.getOrThrow();
        assertEquals(RESPONSE_CODE.NO_ERROR, response.responseCode);
    }

    public static void tcpAsyncApiTest() throws IOException {
        DNSDataSource dataSource = new AsyncNetworkDataSource();
        dataSource.setTimeout(60 * 60 * 1000);
        dataSource.setUdpPayloadSize(256);
        dataSource.setQueryMode(QueryMode.tcp);

        DNSClient client = new DNSClient();
        client.setDataSource(dataSource);
        client.setAskForDnssec(true);

        MiniDnsFuture<DNSMessage, IOException> future = client.queryAsync("google.com", Record.TYPE.AAAA);
        DNSMessage response = future.getOrThrow();
        assertEquals(RESPONSE_CODE.NO_ERROR, response.responseCode);
    }
}
