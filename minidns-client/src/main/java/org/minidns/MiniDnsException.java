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
package org.minidns;

import java.io.IOException;

import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsqueryresult.DnsQueryResult;

public abstract class MiniDnsException extends IOException {
    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    protected MiniDnsException(String message) {
        super(message);
    }

    public static class IdMismatch extends MiniDnsException {

        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        private final DnsMessage request;
        private final DnsMessage response;

        public IdMismatch(DnsMessage request, DnsMessage response) {
            super(getString(request, response));
            assert request.id != response.id;
            this.request = request;
            this.response = response;
        }

        public DnsMessage getRequest() {
            return request;
        }

        public DnsMessage getResponse() {
            return response;
        }

        private static String getString(DnsMessage request, DnsMessage response) {
            return "The response's ID doesn't matches the request ID. Request: " + request.id + ". Response: " + response.id;
        }
    }

    public static class NullResultException extends MiniDnsException {

        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        private final DnsMessage request;

        public NullResultException(DnsMessage request) {
            super("The request yielded a 'null' result while resolving.");
            this.request = request;
        }

        public DnsMessage getRequest() {
            return request;
        }
    }

    public static class ErrorResponseException extends MiniDnsException {

        /**
         *
         */
        private static final long serialVersionUID = 1L;

        private final DnsMessage request;
        private final DnsQueryResult result;

        public ErrorResponseException(DnsMessage request, DnsQueryResult result) {
            super("Received " + result.response.responseCode + " error response\n" + result);
            this.request = request;
            this.result = result;
        }

        public DnsMessage getRequest() {
            return request;
        }

        public DnsQueryResult getResult() {
            return result;
        }
    }

    public static class NoQueryPossibleException extends MiniDnsException {

        /**
         *
         */
        private static final long serialVersionUID = 1L;

        private final DnsMessage request;

        public NoQueryPossibleException(DnsMessage request) {
            super("No DNS server could be queried");
            this.request = request;
        }

        public DnsMessage getRequest() {
            return request;
        }
    }
}
