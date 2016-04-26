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
import java.io.IOException;

import de.measite.minidns.DNSName;
import de.measite.minidns.Record.TYPE;

/**
 * A PTR record is handled like a CNAME.
 */
public class PTR extends CNAME {

    public static PTR parse(DataInputStream dis, byte[] data) throws IOException {
        CNAME cname = CNAME.parse(dis, data);
        return new PTR(cname.name);
    }

    PTR(String name) {
        this(DNSName.from(name));
    }

    PTR(DNSName name) {
        super(name);
    }

    @Override
    public TYPE getType() {
        return TYPE.PTR;
    }

}
