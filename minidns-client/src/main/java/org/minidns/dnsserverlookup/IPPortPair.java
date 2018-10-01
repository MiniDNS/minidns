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
package org.minidns.dnsserverlookup;

import java.io.Serializable;

public class IPPortPair implements Serializable {
    private static final long serialVersionUID = 7354713072355023750L;
    public static final int DEFAULT_PORT = 53;
    private int port;
    private String ip;

    public IPPortPair(String ip) {
        this(ip, DEFAULT_PORT);
    }

    public IPPortPair(String ip, int port) {
        this.port = port;
        this.ip = ip;
    }

    public int getPort() {
        return port;
    }

    public String getIp() {
        return ip;
    }
}
