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

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

/**
 * MX record payload (mail service pointer).
 */
public class MX implements Data {

    /**
     * The priority of this service. Lower values mean higher priority.
     */
    public final int priority;

    /**
     * The name of the target server.
     */
    public final String name;

    public MX(DataInputStream dis, byte[] data, int length)
        throws IOException
    {
        this.priority = dis.readUnsignedShort();
        this.name = NameUtil.parse(dis, data);
    }

    public MX(int priority, String name) {
        this.priority = priority;
        this.name = name;
    }

    @Override
    public byte[] toByteArray() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.writeShort(priority);
            dos.write(NameUtil.toByteArray(name));
        } catch (IOException e) {
            // Should never happen
            throw new RuntimeException(e);
        }

        return baos.toByteArray();
    }

    @Override
    public String toString() {
        return priority + " " + name + '.';
    }

    @Override
    public TYPE getType() {
        return TYPE.MX;
    }

}
