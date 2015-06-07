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
 * AAAA payload (an ipv6 pointer).
 */
public class AAAA implements Data {

    /**
     * The ipv6 address.
     */
    public final byte[] ip;

    @Override
    public TYPE getType() {
        return TYPE.AAAA;
    }

    @Override
    public byte[] toByteArray() {
        return ip;
    }

    public AAAA(DataInputStream dis, byte[] data, int length)
            throws IOException {
        ip = new byte[16];
        dis.readFully(ip);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ip.length; i += 2) {
            if (i != 0) {
                sb.append(':');
            }
            sb.append(Integer.toHexString(
                ((ip[i] & 0xff) << 8) + (ip[i + 1] & 0xff)
            ));
        }
        return sb.toString();
    }

}
