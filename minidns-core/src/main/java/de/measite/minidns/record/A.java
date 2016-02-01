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
package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;

/**
 * A record payload (ip pointer).
 */
public class A implements Data {

    /**
     * Target IP.
     */
    public final byte[] ip;

    @Override
    public TYPE getType() {
        return TYPE.A;
    }

    @Override
    public byte[] toByteArray() {
        return ip;
    }

    public A(byte[] ip) {
        if (ip.length != 4) {
            throw new IllegalArgumentException("IPv4 address in A record is always 4 byte");
        }
        this.ip = ip;
    }

    public A(DataInputStream dis, byte[] data, int length)
            throws IOException {
        ip = new byte[4];
        dis.readFully(ip);
    }

    @Override
    public String toString() {
        return Integer.toString(ip[0] & 0xff) + "." +
               Integer.toString(ip[1] & 0xff) + "." +
               Integer.toString(ip[2] & 0xff) + "." +
               Integer.toString(ip[3] & 0xff);
    }

}
