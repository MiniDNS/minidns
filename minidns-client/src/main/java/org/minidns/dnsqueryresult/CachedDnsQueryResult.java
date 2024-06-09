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

public abstract class CachedDnsQueryResult extends DnsQueryResult {

    protected final DnsQueryResult cachedDnsQueryResult;

    protected CachedDnsQueryResult(DnsMessage query, DnsQueryResult cachedDnsQueryResult) {
        super(QueryMethod.cachedDirect, query, cachedDnsQueryResult.response);
        this.cachedDnsQueryResult = cachedDnsQueryResult;
    }

    protected CachedDnsQueryResult(DnsMessage query, DnsMessage response, DnsQueryResult synthesynthesizationSource) {
        super(QueryMethod.cachedSynthesized, query, response);
        this.cachedDnsQueryResult = synthesynthesizationSource;
    }
}
