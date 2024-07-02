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
package org.minidns.source;

import org.minidns.DnsCache;
import org.minidns.MiniDnsFuture;
import org.minidns.MiniDnsFuture.InternalMiniDnsFuture;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsqueryresult.DnsQueryResult;

import java.io.IOException;
import java.net.InetAddress;

public abstract class AbstractDnsDataSource implements DnsDataSource {

    @Override
    public abstract DnsQueryResult query(DnsMessage message, InetAddress address, int port) throws IOException;

    @Override
    public MiniDnsFuture<DnsQueryResult, IOException> queryAsync(DnsMessage message, InetAddress address, int port, OnResponseCallback onResponseCallback) {
        InternalMiniDnsFuture<DnsQueryResult, IOException> future = new InternalMiniDnsFuture<>();
        DnsQueryResult result;
        try {
            result = query(message, address, port);
        } catch (IOException e) {
            future.setException(e);
            return future;
        }
        future.setResult(result);
        return future;
    }

    protected int udpPayloadSize = 1232;

    /**
     * DNS timeout.
     */
    protected int timeout = 5000;

    @Override
    public int getTimeout() {
        return timeout;
    }

    @Override
    public void setTimeout(int timeout) {
        if (timeout <= 0) {
            throw new IllegalArgumentException("Timeout must be greater than zero");
        }
        this.timeout = timeout;
    }

    @Override
    public int getUdpPayloadSize() {
        return udpPayloadSize;
    }

    public void setUdpPayloadSize(int udpPayloadSize) {
        if (udpPayloadSize <= 0) {
            throw new IllegalArgumentException("UDP payload size must be greater than zero");
        }
        this.udpPayloadSize = udpPayloadSize;
    }

    private DnsCache cache;

    protected final void cacheResult(DnsMessage request, DnsQueryResult response) {
        final DnsCache activeCache = cache;
        if (activeCache == null) {
            return;
        }
        activeCache.put(request, response);
    }

    public enum QueryMode {
        /**
         * Perform the query mode that is assumed "best" for that particular case.
         */
        dontCare,

        /**
         * Try UDP first, and if the result is bigger than the maximum UDP payload size, or if something else goes wrong, fallback to TCP.
         */
        udpTcp,

        /**
         * Always use only TCP when querying DNS servers.
         */
        tcp,
    }

    private QueryMode queryMode = QueryMode.dontCare;

    public void setQueryMode(QueryMode queryMode) {
        if (queryMode == null) {
            throw new IllegalArgumentException();
        }
        this.queryMode = queryMode;
    }

    public QueryMode getQueryMode() {
        return queryMode;
    }

}
