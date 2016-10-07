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
package de.measite.minidns.record;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * A resource record representing a internet address. Provides {@link #getInetAddress()}.
 */
public abstract class InternetAddressRR extends Data {


    /**
     * Target IP.
     */
    protected final byte[] ip;

    /**
     * Cache for the {@link InetAddress} this record presents.
     */
    private InetAddress inetAddress;

    protected InternetAddressRR(byte[] ip) {
        this.ip = ip;
    }

    @Override
    public final void serialize(DataOutputStream dos) throws IOException {
        dos.write(ip);
    }

    /**
     * Allocates a new byte buffer and fills the buffer with the bytes representing the IP address of this resource record.
     *
     * @return a new byte buffer containing the bytes of the IP.
     */
    public final byte[] getIp() {
        return ip.clone();
    }

    public final InetAddress getInetAddress() {
        InetAddress i = this.inetAddress;
        if (i == null) {
            try {
                i = InetAddress.getByAddress(ip);
            } catch (UnknownHostException e) {
                throw new IllegalStateException(e);
            }
            this.inetAddress = i;
        }
        return i;
    }

}
