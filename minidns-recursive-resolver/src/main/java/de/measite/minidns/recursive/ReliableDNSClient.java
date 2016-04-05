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
package de.measite.minidns.recursive;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSCache;
import de.measite.minidns.DNSClient;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.Question;
import de.measite.minidns.source.DNSDataSource;
import de.measite.minidns.util.MultipleIoException;

/**
 * A DNS client using a reliable strategy. First the configured resolver of the
 * system are used, then, in case there is no answer, a fall back to recursively
 * resolving is performed.
 */
public class ReliableDNSClient extends AbstractDNSClient {

    private final RecursiveDNSClient recursiveDnsClient;
    private final DNSClient dnsClient;

    public ReliableDNSClient(DNSCache dnsCache) {
        super(dnsCache);
        recursiveDnsClient = new RecursiveDNSClient(dnsCache) {
            @Override
            protected DNSMessage newQuestion(DNSMessage questionMessage) {
                questionMessage = super.newQuestion(questionMessage);
                return ReliableDNSClient.this.newQuestion(questionMessage);
            }
            @Override
            protected boolean isResponseCacheable(Question q, DNSMessage dnsMessage) {
                boolean res = super.isResponseCacheable(q, dnsMessage);
                return ReliableDNSClient.this.isResponseCacheable(q, dnsMessage) && res;
            }
        };
        dnsClient = new DNSClient(dnsCache) {
            @Override
            protected DNSMessage newQuestion(DNSMessage questionMessage) {
                questionMessage = super.newQuestion(questionMessage);
                return ReliableDNSClient.this.newQuestion(questionMessage);
            }
            @Override
            protected boolean isResponseCacheable(Question q, DNSMessage dnsMessage) {
                boolean res = super.isResponseCacheable(q, dnsMessage);
                return ReliableDNSClient.this.isResponseCacheable(q, dnsMessage) && res;
            }
        };
    }

    public ReliableDNSClient() {
        this(DEFAULT_CACHE);
    }

    @Override
    public DNSMessage query(Question q) throws IOException {
        DNSMessage dnsMessage = null;
        List<IOException> ioExceptions = new LinkedList<>();
        try {
            dnsMessage = dnsClient.query(q);
            if (dnsMessage != null) return dnsMessage;
        } catch (IOException ioException) {
            ioExceptions.add(ioException);
        }

        try {
            dnsMessage = recursiveDnsClient.query(q);
        } catch (IOException ioException) {
            ioExceptions.add(ioException);
        }

        if (dnsMessage == null) {
            MultipleIoException.throwIfRequired(ioExceptions);
        }

        return dnsMessage;
    }

    @Override
    protected DNSMessage newQuestion(DNSMessage questionMessage) {
        return questionMessage;
    }

    @Override
    protected boolean isResponseCacheable(Question q, DNSMessage dnsMessage) {
        return true;
    }

    @Override
    public void setDataSource(DNSDataSource dataSource) {
        super.setDataSource(dataSource);
        recursiveDnsClient.setDataSource(dataSource);
        dnsClient.setDataSource(dataSource);
    }
}
