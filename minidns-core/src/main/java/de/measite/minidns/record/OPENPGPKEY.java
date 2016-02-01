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
import de.measite.minidns.util.Base64;

import java.io.DataInputStream;
import java.io.IOException;

public class OPENPGPKEY implements Data {

    public final byte[] publicKeyPacket;

    public OPENPGPKEY(DataInputStream dis, byte[] data, int length) throws IOException {
        publicKeyPacket = new byte[length];
        dis.readFully(publicKeyPacket);
    }

    OPENPGPKEY(byte[] publicKeyPacket) {
        this.publicKeyPacket = publicKeyPacket;
    }

    @Override
    public Record.TYPE getType() {
        return Record.TYPE.OPENPGPKEY;
    }

    @Override
    public byte[] toByteArray() {
        return publicKeyPacket;
    }

    @Override
    public String toString() {
        return Base64.encodeToString(publicKeyPacket);
    }
}
