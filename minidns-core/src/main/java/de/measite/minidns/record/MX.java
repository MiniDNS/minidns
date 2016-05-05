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

import de.measite.minidns.DNSName;
import de.measite.minidns.Record.TYPE;

/**
 * MX record payload (mail service pointer).
 */
public class MX extends Data {

    /**
     * The priority of this service. Lower values mean higher priority.
     */
    public final int priority;

    /**
     * The name of the target server.
     */
    public final DNSName name;

    public static MX parse(DataInputStream dis, byte[] data)
        throws IOException
    {
        int priority = dis.readUnsignedShort();
        DNSName name = DNSName.parse(dis, data);
        return new MX(priority, name);
    }

    public MX(int priority, String name) {
        this(priority, DNSName.from(name));
    }

    public MX(int priority, DNSName name) {
        this.priority = priority;
        this.name = name;
    }

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        dos.writeShort(priority);
        name.writeToStream(dos);
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
