/*
 * Copyright 2015-2018 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.record;

import java.io.DataOutputStream;
import java.io.IOException;

import de.measite.minidns.DNSName;

/**
 * A resource record pointing to a target.
 */
public abstract class RRWithTarget extends Data {

    public final DNSName target;

    /**
     * The target of this resource record.
     * @deprecated {@link #target} instead.
     */
    @Deprecated
    public final DNSName name;

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        target.writeToStream(dos);
    }

    protected RRWithTarget(DNSName target) {
        this.target = target;
        this.name = target;
    }

    @Override
    public String toString() {
        return target + ".";
    }

    public final DNSName getTarget() {
        return target;
    }
}
