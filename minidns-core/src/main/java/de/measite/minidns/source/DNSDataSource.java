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

import de.measite.minidns.DNSMessage;

import java.io.IOException;
import java.net.InetAddress;

public abstract class DNSDataSource {
    public abstract DNSMessage query(DNSMessage message, InetAddress address, int port) throws IOException;

    protected int udpPayloadSize = 1024;

    /**
     * DNS timeout.
     */
    protected int timeout = 5000;

    /**
     * Retrieve the current dns query timeout, in milliseconds.
     *
     * @return the current dns query timeout in milliseconds.
     */
    public int getTimeout() {
        return timeout;
    }

    /**
     * Change the dns query timeout for all future queries. The timeout
     * must be specified in milliseconds.
     *
     * @param timeout new dns query timeout in milliseconds.
     */
    public void setTimeout(int timeout) {
        if (timeout <= 0) {
            throw new IllegalArgumentException("Timeout must be greater than zero");
        }
        this.timeout = timeout;
    }

    public int getUdpPayloadSize() {
        return udpPayloadSize;
    }

    public void setUdpPayloadSize(int udpPayloadSize) {
        if (udpPayloadSize <= 0) {
            throw new IllegalArgumentException("UDP payload size must be greater than zero");
        }
        this.udpPayloadSize = udpPayloadSize;
    }
}
