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
package de.measite.minidns.source;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSMessage;

public class NetworkDataSourceWithAccounting extends NetworkDataSource {

    private final AtomicInteger successfulQueries = new AtomicInteger();
    private final AtomicInteger responseSize = new AtomicInteger();
    private final AtomicInteger failedQueries = new AtomicInteger();

    private final AtomicInteger successfulUdpQueries = new AtomicInteger();
    private final AtomicInteger udpResponseSize = new AtomicInteger();
    private final AtomicInteger failedUdpQueries = new AtomicInteger();

    private final AtomicInteger successfulTcpQueries = new AtomicInteger();
    private final AtomicInteger tcpResponseSize = new AtomicInteger();
    private final AtomicInteger failedTcpQueries = new AtomicInteger();

    public DNSMessage query(DNSMessage message, InetAddress address, int port) throws IOException {
        DNSMessage response;
        try {
            response = super.query(message, address, port);
        } catch (IOException e) {
            failedQueries.incrementAndGet();
            throw e;
        }

        successfulQueries.incrementAndGet();
        responseSize.addAndGet(response.toArray().length);

        return response;
    }

    protected DNSMessage queryUdp(DNSMessage message, InetAddress address, int port) throws IOException {
        DNSMessage response;
        try {
            response = super.queryUdp(message, address, port);
        } catch (IOException e) {
            failedUdpQueries.incrementAndGet();
            throw e;
        }

        successfulUdpQueries.incrementAndGet();
        udpResponseSize.addAndGet(response.toArray().length);

        return response;
    }

    protected DNSMessage queryTcp(DNSMessage message, InetAddress address, int port) throws IOException {
        DNSMessage response;
        try {
            response = super.queryTcp(message, address, port);
        } catch (IOException e) {
            failedTcpQueries.incrementAndGet();
            throw e;
        }

        successfulTcpQueries.incrementAndGet();
        tcpResponseSize.addAndGet(response.toArray().length);

        return response;
    }

    public Stats getStats() {
        return new Stats(this);
    }

    public static NetworkDataSourceWithAccounting from(AbstractDNSClient client) {
        DNSDataSource ds = client.getDataSource();
        if (ds instanceof NetworkDataSourceWithAccounting) {
            return (NetworkDataSourceWithAccounting) ds;
        }
        return null;
    }

    public static class Stats {
        public final int successfulQueries;
        public final int responseSize;
        public final int averageResponseSize;
        public final int failedQueries;

        public final int successfulUdpQueries;
        public final int udpResponseSize;
        public final int averageUdpResponseSize;
        public final int failedUdpQueries;

        public final int successfulTcpQueries;
        public final int tcpResponseSize;
        public final int averageTcpResponseSize;
        public final int failedTcpQueries;

        private String stringCache;

        private Stats(NetworkDataSourceWithAccounting ndswa) {
            successfulQueries = ndswa.successfulQueries.get();
            responseSize = ndswa.responseSize.get();
            failedQueries = ndswa.failedQueries.get();

            successfulUdpQueries = ndswa.successfulUdpQueries.get();
            udpResponseSize = ndswa.udpResponseSize.get();
            failedUdpQueries = ndswa.failedUdpQueries.get();

            successfulTcpQueries = ndswa.successfulTcpQueries.get();
            tcpResponseSize = ndswa.tcpResponseSize.get();
            failedTcpQueries = ndswa.failedTcpQueries.get();

            // Calculated stats section
            averageResponseSize = successfulQueries > 0 ? responseSize / successfulQueries : 0;
            averageUdpResponseSize = successfulUdpQueries > 0 ? udpResponseSize / successfulUdpQueries : 0;
            averageTcpResponseSize = successfulTcpQueries > 0 ? tcpResponseSize / successfulTcpQueries : 0;
        }

        @Override
        public String toString() {
            if (stringCache != null)
                return stringCache;

            StringBuilder sb = new StringBuilder();

            sb.append("Stats\t").append("# Successful").append('\t').append("# Failed").append('\t')
                    .append("Resp. Size").append('\t').append("Avg. Resp. Size").append('\n');
            sb.append("Total\t").append(toString(successfulQueries)).append('\t').append(toString(failedQueries))
                    .append('\t').append(toString(responseSize)).append('\t').append(toString(averageResponseSize))
                    .append('\n');
            sb.append("UDP\t").append(toString(successfulUdpQueries)).append('\t').append(toString(failedUdpQueries))
                    .append('\t').append(toString(udpResponseSize)).append('\t')
                    .append(toString(averageUdpResponseSize)).append('\n');
            sb.append("TCP\t").append(toString(successfulTcpQueries)).append('\t').append(toString(failedTcpQueries))
                    .append('\t').append(toString(tcpResponseSize)).append('\t')
                    .append(toString(averageTcpResponseSize)).append('\n');

            stringCache = sb.toString();
            return stringCache;
        }

        private static String toString(int i) {
            return String.format(Locale.US, "%,09d", i);
        }
    }
}
