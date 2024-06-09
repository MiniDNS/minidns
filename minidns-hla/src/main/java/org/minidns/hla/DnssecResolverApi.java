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
package org.minidns.hla;

import java.io.IOException;
import java.util.Set;

import org.minidns.DnsCache;
import org.minidns.MiniDnsException.NullResultException;
import org.minidns.cache.LruCache;
import org.minidns.cache.MiniDnsCacheFactory;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsname.DnsName;
import org.minidns.dnssec.DnssecClient;
import org.minidns.dnssec.DnssecQueryResult;
import org.minidns.dnssec.DnssecUnverifiedReason;
import org.minidns.iterative.ReliableDnsClient.Mode;
import org.minidns.record.Data;
import org.minidns.record.Record.TYPE;

public class DnssecResolverApi extends ResolverApi {

    public static final DnssecResolverApi INSTANCE = new DnssecResolverApi();

    private final DnssecClient dnssecClient;
    private final DnssecClient iterativeOnlyDnssecClient;
    private final DnssecClient recursiveOnlyDnssecClient;

    public DnssecResolverApi() {
        this(new MiniDnsCacheFactory() {
            @Override
            public DnsCache newCache() {
                return new LruCache();
            }
        });
    }

    public DnssecResolverApi(MiniDnsCacheFactory cacheFactory) {
        this(new DnssecClient(cacheFactory.newCache()), cacheFactory);
    }

    private DnssecResolverApi(DnssecClient dnssecClient, MiniDnsCacheFactory cacheFactory) {
        super(dnssecClient);
        this.dnssecClient = dnssecClient;

        // Set the *_ONLY_DNSSEC ResolverApi. It is important that the two do *not* share the same cache, since we
        // probably fall back to iterativeOnly and in that case do not want the cached results of the recursive result.
        iterativeOnlyDnssecClient = new DnssecClient(cacheFactory.newCache());
        iterativeOnlyDnssecClient.setMode(Mode.iterativeOnly);

        recursiveOnlyDnssecClient = new DnssecClient(cacheFactory.newCache());
        recursiveOnlyDnssecClient.setMode(Mode.recursiveOnly);
    }

    @Override
    public <D extends Data> ResolverResult<D> resolve(Question question) throws IOException {
        DnssecQueryResult dnssecMessage = dnssecClient.queryDnssec(question);
        return toResolverResult(question, dnssecMessage);
    }

    /**
     * Resolve the given name and type which is expected to yield DNSSEC authenticated results.
     *
     * @param name the DNS name to resolve.
     * @param type the class of the RR type to resolve.
     * @param <D> the RR type to resolve.
     * @return the resolver result.
     * @throws IOException in case an exception happens while resolving.
     * @see #resolveDnssecReliable(Question)
     */
    public <D extends Data> ResolverResult<D> resolveDnssecReliable(String name, Class<D> type) throws IOException {
        return resolveDnssecReliable(DnsName.from(name), type);
    }

    /**
     * Resolve the given name and type which is expected to yield DNSSEC authenticated results.
     *
     * @param name the DNS name to resolve.
     * @param type the class of the RR type to resolve.
     * @param <D> the RR type to resolve.
     * @return the resolver result.
     * @throws IOException in case an exception happens while resolving.
     * @see #resolveDnssecReliable(Question)
     */
    public <D extends Data> ResolverResult<D> resolveDnssecReliable(DnsName name, Class<D> type) throws IOException {
        TYPE t = TYPE.getType(type);
        Question q = new Question(name, t);
        return resolveDnssecReliable(q);
    }

    /**
     * Resolve the given question which is expected to yield DNSSEC authenticated results.
     *
     * @param question the question to resolve.
     * @param <D> the RR type to resolve.
     * @return the resolver result.
     * @throws IOException in case an exception happens while resolving.
     */
    public <D extends Data> ResolverResult<D> resolveDnssecReliable(Question question) throws IOException {
        DnssecQueryResult dnssecMessage = recursiveOnlyDnssecClient.queryDnssec(question);
        if (dnssecMessage == null || !dnssecMessage.isAuthenticData()) {
            dnssecMessage = iterativeOnlyDnssecClient.queryDnssec(question);
        }
        return toResolverResult(question, dnssecMessage);
    }

    public DnssecClient getDnssecClient() {
        return dnssecClient;
    }

    private static <D extends Data> ResolverResult<D> toResolverResult(Question question, DnssecQueryResult dnssecMessage) throws NullResultException {
        Set<DnssecUnverifiedReason> unverifiedReasons = dnssecMessage.getUnverifiedReasons();

        return new ResolverResult<D>(question, dnssecMessage.dnsQueryResult, unverifiedReasons);
    }
}
