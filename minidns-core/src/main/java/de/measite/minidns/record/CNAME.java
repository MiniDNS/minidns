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
 * CNAME payload (pointer to another domain / address).
 */
public class CNAME implements Data {

    public final String name;

    @Override
    public byte[] toByteArray() {
        return NameUtil.toByteArray(name);
    }

    public static CNAME parse(DataInputStream dis, byte[] data, int length) throws IOException {
        String name = NameUtil.parse(dis, data);
        return new CNAME(name);
    }

    public CNAME(String name) {
        this.name = name;
    }

    @Override
    public TYPE getType() {
        return TYPE.CNAME;
    }

    @Override
    public String toString() {
        return name + ".";
    }

}
