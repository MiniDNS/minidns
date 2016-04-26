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
package de.measite.minidns.recursive;

import de.measite.minidns.MiniDNSException;

public abstract class RecursiveClientException extends MiniDNSException {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    protected RecursiveClientException(String message) {
        super(message);
    }

    public static class LoopDetected extends RecursiveClientException {

        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        public LoopDetected() {
            super("Recursion loop detected");
        }

    }

    public static class MaxRecursionStepsReached extends RecursiveClientException {

        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        public MaxRecursionStepsReached() {
            super("Maxmimum recursion steps reached");
        }

    }
}
