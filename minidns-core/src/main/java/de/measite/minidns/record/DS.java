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

import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * DS record payload.
 */
public class DS implements Data {

    /**
     * The key tag value of the DNSKEY RR that validates this signature.
     */
    public final int /* unsigned short */ keyTag;

    /**
     * The cryptographic algorithm used to create the signature.
     */
    public final byte algorithm;

    /**
     * The algorithm used to construct the digest.
     */
    public final byte digestType;

    /**
     * The digest build from a DNSKEY.
     */
    public final byte[] digest;

    public DS(DataInputStream dis, byte[] data, int length) throws IOException {
        keyTag = dis.readUnsignedShort();
        algorithm = dis.readByte();
        digestType = dis.readByte();
        digest = new byte[length - 4];
        dis.read(digest);
    }

    @Override
    public TYPE getType() {
        return TYPE.DS;
    }

    @Override
    public byte[] toByteArray() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder()
                .append(keyTag).append(' ')
                .append(algorithm).append(' ')
                .append(digestType).append(' ')
                .append(new BigInteger(1, digest).toString(16).toUpperCase());
        return sb.toString();
    }
}
