/*
 * Copyright 2015-2017 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns;

public abstract class InvalidDNSNameException extends IllegalStateException {

    private static final long serialVersionUID = 1L;

    protected final String ace;

    protected InvalidDNSNameException(String ace) {
        this.ace = ace;
    }

    public static class LabelTooLongException extends InvalidDNSNameException {
        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        private final String label;

        public LabelTooLongException(String ace, String label) {
            super(ace);
            this.label = label;
        }

        @Override
        public String getMessage() {
            return "The DNS name '" + ace + "' contains the label '" + label
                    + "' which exceeds the maximum label length of " + DNSName.MAX_LABEL_LENGTH_IN_OCTETS + " octets by "
                    + (label.length() - DNSName.MAX_LABEL_LENGTH_IN_OCTETS) + " octets.";
        }
    }

    public static class DNSNameTooLongException extends InvalidDNSNameException {
        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        private final byte[] bytes;

        public DNSNameTooLongException(String ace, byte[] bytes) {
            super(ace);
            this.bytes = bytes;
        }

        @Override
        public String getMessage() {
            return "The DNS name '" + ace + "' exceeds the maximum name length of "
                    + DNSName.MAX_DNSNAME_LENGTH_IN_OCTETS + " octets by "
                    + (bytes.length - DNSName.MAX_DNSNAME_LENGTH_IN_OCTETS) + " octets.";
        }
    }
}
