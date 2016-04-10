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
package de.measite.minidns.hla;

import java.io.IOException;
import java.util.Set;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.DNSName;
import de.measite.minidns.Question;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.dnssec.DNSSECClient;
import de.measite.minidns.dnssec.DNSSECMessage;
import de.measite.minidns.dnssec.UnverifiedReason;
import de.measite.minidns.record.Data;
import de.measite.minidns.recursive.ReliableDNSClient;

public class ResolverApi {

    public static final ResolverApi DNSSEC = new ResolverApi(new DNSSECClient());
    public static final ResolverApi NON_DNSSEC = new ResolverApi(new ReliableDNSClient());

    private final AbstractDNSClient dnsClient;
    private final DNSSECClient dnssecClient;

    public ResolverApi(AbstractDNSClient dnsClient) {
        if (dnsClient instanceof DNSSECClient) {
            this.dnssecClient = (DNSSECClient) dnsClient;
            this.dnsClient = null;
        } else {
            this.dnssecClient = null;
            this.dnsClient = dnsClient;
        }
    }

    public <D extends Data> ResolverResult<D> resolve(String name, Class<D> type) throws IOException {
        return resolve(DNSName.from(name), type);
    }

    public <D extends Data> ResolverResult<D> resolve(DNSName name, Class<D> type) throws IOException {
        TYPE t = TYPE.getType(type);
        Question q = new Question(name, t);
        return resolve(q);
    }

    public <D extends Data> ResolverResult<D> resolve(Question question) throws IOException {
        DNSMessage dnsMessage;
        Set<UnverifiedReason> unverifiedReasons = null;
        if (dnssecClient != null) {
            DNSSECMessage dnssecMessage = dnssecClient.queryDnssec(question);
            unverifiedReasons = dnssecMessage.getUnverifiedReasons();
            dnsMessage = dnssecMessage;
        } else {
            dnsMessage = dnsClient.query(question);
        }

        return new ResolverResult<D>(question, dnsMessage, unverifiedReasons);
    }

    public AbstractDNSClient getClient() {
        if (dnssecClient != null) {
            return dnssecClient;
        } else {
            return dnsClient;
        }
    }
}
