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
package org.minidns.dnsqueryresult;

import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.DnsMessage.RESPONSE_CODE;

public abstract class DnsQueryResult {

    public enum QueryMethod {
        udp,
        tcp,
        asyncUdp,
        asyncTcp,
        cachedDirect,
        cachedSynthesized,
        testWorld,
    }

    public final QueryMethod queryMethod;

    public final DnsMessage query;

    public final DnsMessage response;

    protected DnsQueryResult(QueryMethod queryMethod, DnsMessage query, DnsMessage response) {
        assert queryMethod != null;
        assert query != null;
        assert response != null;

        this.queryMethod = queryMethod;
        this.query = query;
        this.response = response;
    }

    @Override
    public String toString() {
        return response.toString();
    }

    public boolean wasSuccessful() {
        return response.responseCode == RESPONSE_CODE.NO_ERROR;
    }
}
