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
package org.minidns.record;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.minidns.record.Record.TYPE;

public final class UNKNOWN extends Data {

    private final int typeValue;
    private final byte[] data;

    private UNKNOWN(DataInputStream dis, int payloadLength, int typeValue) throws IOException {
        this.typeValue = typeValue;
        this.data = new byte[payloadLength];
        dis.readFully(data);
    }

    @Override
    public TYPE getType() {
        return TYPE.getType(typeValue);
    }

    /**
     * Get the binary type value of this payload. In contrast to {@link #getType()}, this also returns the actual value
     * if the type is unknown to MiniDNS.
     *
     * @return the binary type value.
     */
    public int getTypeValue() {
        return typeValue;
    }

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        dos.write(data);
    }

    public static UNKNOWN parse(DataInputStream dis, int payloadLength, int typeValue)
            throws IOException {
        return new UNKNOWN(dis, payloadLength, typeValue);
    }

    /**
     * Parse an UNKNOWN payload.
     *
     * @param dis the input stream.
     * @param payloadLength the length of the payload.
     * @param type the type of the payload.
     * @return the parsed payload.
     * @throws IOException in case of an I/O error.
     * @deprecated use {@link #parse(DataInputStream, int, int)} instead, as this loses the actual binary type value if
     *             the type is unknown to MiniDNS.
     */
    @Deprecated
    public static UNKNOWN parse(DataInputStream dis, int payloadLength, TYPE type)
            throws IOException {
        return parse(dis, payloadLength, type.getValue());
    }

}
