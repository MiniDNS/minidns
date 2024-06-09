/*
 * Copyright 2015-2024 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.iterative;

import java.net.InetAddress;

import org.minidns.MiniDnsException;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsname.DnsName;
import org.minidns.dnsqueryresult.DnsQueryResult;

public abstract class IterativeClientException extends MiniDnsException {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    protected IterativeClientException(String message) {
        super(message);
    }

    public static class LoopDetected extends IterativeClientException {

        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        public final InetAddress address;
        public final Question question;

        public LoopDetected(InetAddress address, Question question) {
            super("Resolution loop detected: We already asked " + address + " about " + question);
            this.address = address;
            this.question = question;
        }

    }

    public static class MaxIterativeStepsReached extends IterativeClientException {

        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        public MaxIterativeStepsReached() {
            super("Maxmimum steps reached");
        }

    }

    public static class NotAuthoritativeNorGlueRrFound extends IterativeClientException {

        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        private final DnsMessage request;
        private final DnsQueryResult result;
        private final DnsName authoritativeZone;

        public NotAuthoritativeNorGlueRrFound(DnsMessage request, DnsQueryResult result, DnsName authoritativeZone) {
            super("Did not receive an authoritative answer, nor did the result contain any glue records");
            this.request = request;
            this.result = result;
            this.authoritativeZone = authoritativeZone;
        }

        public DnsMessage getRequest() {
            return request;
        }

        public DnsQueryResult getResult() {
            return result;
        }

        public DnsName getAuthoritativeZone() {
            return authoritativeZone;
        }
    }
}
