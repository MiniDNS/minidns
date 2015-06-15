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

import de.measite.minidns.Record;
import de.measite.minidns.Record.TYPE;

import java.io.DataInputStream;
import java.io.IOException;

/**
 * OPT payload (see RFC 2671 for details).
 */
public class OPT implements Data {

    /**
     * Inform the dns server that the client supports DNSSEC.
     */
    public static final int FLAG_DNSSEC_OK = 0x8000;

    /**
     * Raw encoded RDATA of an OPT RR.
     */
    public final byte[] encodedOptData;

    public OPT() {
        encodedOptData = new byte[0];
    }

    public OPT(DataInputStream dis, byte[] data, int payloadLength) throws IOException {
        encodedOptData = new byte[payloadLength];
        dis.read(encodedOptData);
    }

    @Override
    public TYPE getType() {
        return TYPE.OPT;
    }

    @Override
    public byte[] toByteArray() {
        return encodedOptData;
    }

    public static String toString(Record record) {
        StringBuilder sb = new StringBuilder("EDNS: version: ").append((record.ttl >> 16) & 0xff).append(", flags:");
        if ((record.ttl & FLAG_DNSSEC_OK) > 0) sb.append(" do");
        return sb.append("; udp: ").append(record.clazzValue).toString();
    }
}
