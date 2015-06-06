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

/**
 * Generic payload class.
 */
public interface Data {

    /**
     * The payload type.
     * @return The payload type.
     */
    TYPE getType();

    /**
     * Binary representation of this payload.
     * @return The binary representation of this payload.
     */
    byte[] toByteArray();

}
