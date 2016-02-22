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
package de.measite.minidns.util;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class MultipleIoException extends IOException {

    /**
     * 
     */
    private static final long serialVersionUID = -5932211337552319515L;

    private final List<IOException> ioExceptions;

    public MultipleIoException(List<IOException> ioExceptions) {
        super(getMessage(ioExceptions));
        if (ioExceptions == null || ioExceptions.isEmpty()) {
            throw new IllegalArgumentException();
        }
        this.ioExceptions = Collections.unmodifiableList(ioExceptions);
    }

    public List<IOException> getExceptions() {
        return ioExceptions;
    }

    private static String getMessage(Collection<? extends Exception> exceptions) {
        StringBuilder sb = new StringBuilder();
        Iterator<? extends Exception> it = exceptions.iterator();
        while (it.hasNext()) {
            sb.append(it.next().getMessage());
            if (it.hasNext()) {
                sb.append(", ");
            }
        }
        return sb.toString();
    }
}
