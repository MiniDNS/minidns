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

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

import java.io.DataInputStream;
import java.io.IOException;

/**
 * SOA (start of authority) record payload.
 */
public class SOA implements Data {

    /**
     * The domain name of the name server that was the original or primary source of data for this zone.
     */
    public final String mname;

    /**
     * A domain name which specifies the mailbox of the person responsible for this zone.
     */
    public final String rname;

    /**
     * The unsigned 32 bit version number of the original copy of the zone.  Zone transfers preserve this value.  This
     * value wraps and should be compared using sequence space arithmetic.
     */
    public final long /* unsigned int */ serial;

    /**
     * A 32 bit time interval before the zone should be refreshed.
     */
    public final int refresh;

    /**
     * A 32 bit time interval that should elapse before a failed refresh should be retried.
     */
    public final int retry;

    /**
     * A 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no
     * longer authoritative.
     */
    public final int expire;

    /**
     * The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.
     */
    public final long /* unsigned int */ minimum;

    public SOA(DataInputStream dis, byte[] data, int length)
            throws IOException {
        mname = NameUtil.parse(dis, data);
        rname = NameUtil.parse(dis, data);
        serial = dis.readInt() & 0xFFFFFFFFL;
        refresh = dis.readInt();
        retry = dis.readInt();
        expire = dis.readInt();
        minimum = dis.readInt() & 0xFFFFFFFFL;
    }

    @Override
    public TYPE getType() {
        return TYPE.SOA;
    }

    @Override
    public byte[] toByteArray() {
        throw new UnsupportedOperationException("Not implemented yet");
    }
}
