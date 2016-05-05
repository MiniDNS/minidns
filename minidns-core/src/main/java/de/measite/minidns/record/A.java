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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;

/**
 * A record payload (ip pointer).
 */
public class A extends Data {

    /**
     * Target IP.
     */
    private final byte[] ip;

    @Override
    public TYPE getType() {
        return TYPE.A;
    }

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        dos.write(ip);
    }

    public A(int q1, int q2, int q3, int q4) {
        if (q1 < 0 || q1 > 255 || q2 < 0 || q2 > 255 || q3 < 0 || q3 > 255 || q4 < 0 || q4 > 255) {
            throw new IllegalArgumentException();
        }
        this.ip = new byte[] { (byte) q1, (byte) q2, (byte) q3, (byte) q4 };
    }

    public A(byte[] ip) {
        if (ip.length != 4) {
            throw new IllegalArgumentException("IPv4 address in A record is always 4 byte");
        }
        this.ip = ip;
    }

    public byte[] getIp() {
        return ip.clone();
    }

    public static A parse(DataInputStream dis)
            throws IOException {
        byte[] ip = new byte[4];
        dis.readFully(ip);
        return new A(ip);
    }

    @Override
    public String toString() {
        return Integer.toString(ip[0] & 0xff) + "." +
               Integer.toString(ip[1] & 0xff) + "." +
               Integer.toString(ip[2] & 0xff) + "." +
               Integer.toString(ip[3] & 0xff);
    }

}
