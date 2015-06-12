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

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;

/**
 * Nameserver record.
 */
public class NS extends CNAME {

    public NS(DataInputStream dis, byte[] data, int length) throws IOException {
        super(dis, data, length);
    }

    public NS(String name) {
        super(name);
    }

    @Override
    public TYPE getType() {
        return TYPE.NS;
    }

}
