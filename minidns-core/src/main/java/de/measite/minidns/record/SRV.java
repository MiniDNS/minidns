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
 * SRV record payload (service pointer).
 */
public class SRV extends Data {

    /**
     * The priority of this service. Lower values mean higher priority.
     */
    public final int priority;

    /**
     * The weight of this service. Services with the same priority should be
     * balanced based on weight.
     */
    public final int weight;

    /**
     * The target port.
     */
    public final int port;

    /**
     * The target server.
     */
    public final DNSName name;

    public static SRV parse(DataInputStream dis, byte[] data)
        throws IOException
    {
        int priority = dis.readUnsignedShort();
        int weight = dis.readUnsignedShort();
        int port = dis.readUnsignedShort();
        DNSName name = DNSName.parse(dis, data);
        return new SRV(priority, weight, port, name);
    }

    public SRV(int priority, int weight, int port, String name) {
        this(priority, weight, port, DNSName.from(name));
    }

    public SRV(int priority, int weight, int port, DNSName name) {
        this.priority = priority;
        this.weight = weight;
        this.port = port;
        this.name = name;
    }

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        dos.writeShort(priority);
        dos.writeShort(weight);
        dos.writeShort(port);
        name.writeToStream(dos);
    }

    @Override
    public String toString() {
        return priority + " " + weight + " " + port + " " + name + ".";
    }

    @Override
    public TYPE getType() {
        return TYPE.SRV;
    }

}
