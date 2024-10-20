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

import java.io.IOException;
import java.net.InetAddress;

import org.minidns.MiniDnsFuture;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsqueryresult.DnsQueryResult;

public interface DnsDataSource {

    DnsQueryResult query(DnsMessage message, InetAddress address, int port) throws IOException;

    MiniDnsFuture<DnsQueryResult, IOException> queryAsync(DnsMessage message, InetAddress address, int port, OnResponseCallback onResponseCallback);

    int getUdpPayloadSize();

    /**
     * Retrieve the current dns query timeout, in milliseconds.
     *
     * @return the current dns query timeout in milliseconds.
     */
    int getTimeout();

    /**
     * Change the dns query timeout for all future queries. The timeout
     * must be specified in milliseconds.
     *
     * @param timeout new dns query timeout in milliseconds.
     */
    void setTimeout(int timeout);

    interface OnResponseCallback {
        void onResponse(DnsMessage request, DnsQueryResult result);
    }

}
