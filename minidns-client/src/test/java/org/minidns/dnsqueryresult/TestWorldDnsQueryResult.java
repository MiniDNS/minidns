/*
 * Copyright 2015-2022 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.dnsqueryresult;

import org.minidns.DnsWorld.PreparedResponse;
import org.minidns.dnsmessage.DnsMessage;

public class TestWorldDnsQueryResult extends DnsQueryResult {

    public final PreparedResponse preparedResponse;

    public TestWorldDnsQueryResult(DnsMessage query, DnsMessage response) {
        this(query, response, null);
    }

    public TestWorldDnsQueryResult(DnsMessage query, DnsMessage response, PreparedResponse preparedResponse) {
        super(QueryMethod.testWorld, query, response);
        this.preparedResponse = preparedResponse;
    }

}
