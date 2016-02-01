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

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
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
     *
     * See {@link de.measite.minidns.DNSSECConstants} for possible values.
     */
    public final byte algorithm;

    /**
     * The algorithm used to construct the digest.
     *
     * See {@link de.measite.minidns.DNSSECConstants} for possible values.
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
        if (dis.read(digest) != digest.length) throw new IOException();
    }

    public DS(int keyTag, byte algorithm, byte digestType, byte[] digest) {
        this.keyTag = keyTag;
        this.algorithm = algorithm;
        this.digestType = digestType;
        this.digest = digest;
    }

    @Override
    public TYPE getType() {
        return TYPE.DS;
    }

    @Override
    public byte[] toByteArray() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.writeShort(keyTag);
            dos.writeByte(algorithm);
            dos.writeByte(digestType);
            dos.write(digest);
        } catch (IOException e) {
            // Should never happen
            throw new RuntimeException(e);
        }

        return baos.toByteArray();
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
