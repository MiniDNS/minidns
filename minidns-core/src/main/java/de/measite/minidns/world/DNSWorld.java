/*
 * Copyright 2015 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.world;

import de.measite.minidns.DNSMessage;

import java.net.InetAddress;

public abstract class DNSWorld {
    public abstract DNSMessage query(DNSMessage message, InetAddress address, int port);

    private int udpPayloadSize = 512;

    /**
     * The buffer size for dns replies.
     */
    protected int bufferSize = 1500;

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
        this.timeout = timeout;
    }

    public int getUdpPayloadSize() {
        return Math.min(udpPayloadSize, bufferSize);
    }

    public void setUdpPayloadSize(int udpPayloadSize) {
        this.udpPayloadSize = udpPayloadSize;
    }
}
