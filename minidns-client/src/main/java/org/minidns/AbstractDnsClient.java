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

import org.minidns.MiniDnsFuture.InternalMiniDnsFuture;
import org.minidns.cache.LruCache;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsname.DnsName;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.record.A;
import org.minidns.record.AAAA;
import org.minidns.record.Data;
import org.minidns.record.NS;
import org.minidns.record.Record;
import org.minidns.record.Record.CLASS;
import org.minidns.record.Record.TYPE;
import org.minidns.source.DnsDataSource;
import org.minidns.source.NetworkDataSource;

import java.io.IOException;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A minimal DNS client for SRV/A/AAAA/NS and CNAME lookups, with IDN support.
 * This circumvents the missing javax.naming package on android.
 */
public abstract class AbstractDnsClient {

    protected static final LruCache DEFAULT_CACHE = new LruCache();

    protected static final Logger LOGGER = Logger.getLogger(AbstractDnsClient.class.getName());

    /**
     * This callback is used by the synchronous query() method <b>and</b> by the asynchronous queryAync() method in order to update the
     * cache. In the asynchronous case, hand this callback into the async call, so that it can get called once the result is available.
     */
    private final DnsDataSource.OnResponseCallback onResponseCallback = new DnsDataSource.OnResponseCallback() {
        @Override
        public void onResponse(DnsMessage requestMessage, DnsQueryResult responseMessage) {
            final Question q = requestMessage.getQuestion();
            if (cache != null && isResponseCacheable(q, responseMessage)) {
                cache.put(requestMessage.asNormalizedVersion(), responseMessage);
            }
        }
    };

    /**
     * The internal random class for sequence generation.
     */
    protected final Random random;

    protected final Random insecureRandom = new Random();

    /**
     * The internal DNS cache.
     */
    protected final DnsCache cache;

    protected DnsDataSource dataSource = new NetworkDataSource();

    public enum IpVersionSetting {

        v4only(true, false),
        v6only(false, true),
        v4v6(true, true),
        v6v4(true, true),
        ;

        public final boolean v4;
        public final boolean v6;

        IpVersionSetting(boolean v4, boolean v6) {
            this.v4 = v4;
            this.v6 = v6;
        }

    }

    protected static IpVersionSetting DEFAULT_IP_VERSION_SETTING = IpVersionSetting.v4v6;

    public static void setDefaultIpVersion(IpVersionSetting preferedIpVersion) {
        if (preferedIpVersion == null) {
            throw new IllegalArgumentException();
        }
        AbstractDnsClient.DEFAULT_IP_VERSION_SETTING = preferedIpVersion;
    }

    protected IpVersionSetting ipVersionSetting = DEFAULT_IP_VERSION_SETTING;

    public void setPreferedIpVersion(IpVersionSetting preferedIpVersion) {
        if (preferedIpVersion == null) {
            throw new IllegalArgumentException();
        }
        ipVersionSetting = preferedIpVersion;
    }

    public IpVersionSetting getPreferedIpVersion() {
        return ipVersionSetting;
    }

    /**
     * Create a new DNS client with the given DNS cache.
     *
     * @param cache The backend DNS cache.
     */
    protected AbstractDnsClient(DnsCache cache) {
        Random random;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e1) {
            random = new SecureRandom();
        }
        this.random = random;
        this.cache = cache;
    }

    /**
     * Create a new DNS client using the global default cache.
     */
    protected AbstractDnsClient() {
        this(DEFAULT_CACHE);
    }

    /**
     * Query the system nameservers for a single entry of any class.
     *
     * This can be used to determine the name server version, if name
     * is version.bind, type is TYPE.TXT and clazz is CLASS.CH.
     *
     * @param name  The DNS name to request.
     * @param type  The DNS type to request (SRV, A, AAAA, ...).
     * @param clazz The class of the request (usually IN for Internet).
     * @return The response (or null on timeout/error).
     * @throws IOException if an IO error occurs.
     */
    public final DnsQueryResult query(String name, TYPE type, CLASS clazz) throws IOException {
        Question q = new Question(name, type, clazz);
        return query(q);
    }

    /**
     * Query the system nameservers for a single entry of the class IN
     * (which is used for MX, SRV, A, AAAA and most other RRs).
     *
     * @param name The DNS name to request.
     * @param type The DNS type to request (SRV, A, AAAA, ...).
     * @return The response (or null on timeout/error).
     * @throws IOException if an IO error occurs.
     */
    public final DnsQueryResult query(DnsName name, TYPE type) throws IOException {
        Question q = new Question(name, type, CLASS.IN);
        return query(q);
    }

    /**
     * Query the system nameservers for a single entry of the class IN
     * (which is used for MX, SRV, A, AAAA and most other RRs).
     *
     * @param name The DNS name to request.
     * @param type The DNS type to request (SRV, A, AAAA, ...).
     * @return The response (or null on timeout/error).
     * @throws IOException if an IO error occurs.
     */
    public final DnsQueryResult query(CharSequence name, TYPE type) throws IOException {
        Question q = new Question(name, type, CLASS.IN);
        return query(q);
    }

    public DnsQueryResult query(Question q) throws IOException {
        DnsMessage.Builder query = buildMessage(q);
        return query(query);
    }

    /**
     * Send a query request to the DNS system.
     *
     * @param query The query to send to the server.
     * @return The response (or null).
     * @throws IOException if an IO error occurs.
     */
    protected abstract DnsQueryResult query(DnsMessage.Builder query) throws IOException;

    public final MiniDnsFuture<DnsQueryResult, IOException> queryAsync(CharSequence name, TYPE type) {
        Question q = new Question(name, type, CLASS.IN);
        return queryAsync(q);
    }

    public final MiniDnsFuture<DnsQueryResult, IOException> queryAsync(Question q) {
        DnsMessage.Builder query = buildMessage(q);
        return queryAsync(query);
    }

    /**
     * Default implementation of an asynchronous DNS query which just wraps the synchronous case.
     * <p>
     * Subclasses override this method to support true asynchronous queries.
     * </p>
     *
     * @param query the query.
     * @return a future for this query.
     */
    protected MiniDnsFuture<DnsQueryResult, IOException> queryAsync(DnsMessage.Builder query) {
        InternalMiniDnsFuture<DnsQueryResult, IOException> future = new InternalMiniDnsFuture<>();
        DnsQueryResult result;
        try {
            result = query(query);
        } catch (IOException e) {
            future.setException(e);
            return future;
        }
        future.setResult(result);
        return future;
    }

    public final DnsQueryResult query(Question q, InetAddress server, int port) throws IOException {
        DnsMessage query = getQueryFor(q);
        return query(query, server, port);
    }

    public final DnsQueryResult query(DnsMessage requestMessage, InetAddress address, int port) throws IOException {
        // See if we have the answer to this question already cached
        DnsQueryResult responseMessage = (cache == null) ? null : cache.get(requestMessage);
        if (responseMessage != null) {
            return responseMessage;
        }

        final Question q = requestMessage.getQuestion();

        final Level TRACE_LOG_LEVEL = Level.FINE;
        LOGGER.log(TRACE_LOG_LEVEL, "Asking {0} on {1} for {2} with:\n{3}", new Object[] { address, port, q, requestMessage });

        try {
            responseMessage = dataSource.query(requestMessage, address, port);
        } catch (IOException e) {
            LOGGER.log(TRACE_LOG_LEVEL, "IOException {0} on {1} while resolving {2}: {3}", new Object[] { address, port, q, e});
            throw e;
        }

        LOGGER.log(TRACE_LOG_LEVEL, "Response from {0} on {1} for {2}:\n{3}", new Object[] { address, port, q, responseMessage });

        onResponseCallback.onResponse(requestMessage, responseMessage);

        return responseMessage;
    }

    public final MiniDnsFuture<DnsQueryResult, IOException> queryAsync(DnsMessage requestMessage, InetAddress address, int port) {
        // See if we have the answer to this question already cached
        DnsQueryResult responseMessage = (cache == null) ? null : cache.get(requestMessage);
        if (responseMessage != null) {
            return MiniDnsFuture.from(responseMessage);
        }

        final Question q = requestMessage.getQuestion();

        final Level TRACE_LOG_LEVEL = Level.FINE;
        LOGGER.log(TRACE_LOG_LEVEL, "Asynchronusly asking {0} on {1} for {2} with:\n{3}", new Object[] { address, port, q, requestMessage });

        return dataSource.queryAsync(requestMessage, address, port, onResponseCallback);
    }

    /**
     * Whether a response from the DNS system should be cached or not.
     *
     * @param q          The question the response message should answer.
     * @param result The DNS query result.
     * @return True, if the response should be cached, false otherwise.
     */
    protected boolean isResponseCacheable(Question q, DnsQueryResult result) {
        DnsMessage dnsMessage = result.response;
        for (Record<? extends Data> record : dnsMessage.answerSection) {
            if (record.isAnswer(q)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds a {@link DnsMessage} object carrying the given Question.
     *
     * @param question {@link Question} to be put in the DNS request.
     * @return A {@link DnsMessage} requesting the answer for the given Question.
     */
    final DnsMessage.Builder buildMessage(Question question) {
        DnsMessage.Builder message = DnsMessage.builder();
        message.setQuestion(question);
        message.setId(random.nextInt());
        message = newQuestion(message);
        return message;
    }

    protected abstract DnsMessage.Builder newQuestion(DnsMessage.Builder questionMessage);

    /**
     * Query a nameserver for a single entry.
     *
     * @param name    The DNS name to request.
     * @param type    The DNS type to request (SRV, A, AAAA, ...).
     * @param clazz   The class of the request (usually IN for Internet).
     * @param address The DNS server address.
     * @param port    The DNS server port.
     * @return The response (or null on timeout / failure).
     * @throws IOException On IO Errors.
     */
    public DnsQueryResult query(String name, TYPE type, CLASS clazz, InetAddress address, int port)
            throws IOException {
        Question q = new Question(name, type, clazz);
        return query(q, address, port);
    }

    /**
     * Query a nameserver for a single entry.
     *
     * @param name    The DNS name to request.
     * @param type    The DNS type to request (SRV, A, AAAA, ...).
     * @param clazz   The class of the request (usually IN for Internet).
     * @param address The DNS server host.
     * @return The response (or null on timeout / failure).
     * @throws IOException On IO Errors.
     */
    public DnsQueryResult query(String name, TYPE type, CLASS clazz, InetAddress address)
            throws IOException {
        Question q = new Question(name, type, clazz);
        return query(q, address);
    }

    /**
     * Query a nameserver for a single entry of class IN.
     *
     * @param name    The DNS name to request.
     * @param type    The DNS type to request (SRV, A, AAAA, ...).
     * @param address The DNS server host.
     * @return The response (or null on timeout / failure).
     * @throws IOException On IO Errors.
     */
    public DnsQueryResult query(String name, TYPE type, InetAddress address)
            throws IOException {
        Question q = new Question(name, type, CLASS.IN);
        return query(q, address);
    }

    public final DnsQueryResult query(DnsMessage query, InetAddress host) throws IOException {
        return query(query, host, 53);
    }

    /**
     * Query a specific server for one entry.
     *
     * @param q       The question section of the DNS query.
     * @param address The dns server address.
     * @return The a DNS query result.
     * @throws IOException On IOErrors.
     */
    public DnsQueryResult query(Question q, InetAddress address) throws IOException {
        return query(q, address, 53);
    }

    public final MiniDnsFuture<DnsQueryResult, IOException> queryAsync(DnsMessage query, InetAddress dnsServer) {
        return queryAsync(query, dnsServer, 53);
    }

    /**
     * Returns the currently used {@link DnsDataSource}. See {@link #setDataSource(DnsDataSource)} for details.
     *
     * @return The currently used {@link DnsDataSource}
     */
    public DnsDataSource getDataSource() {
        return dataSource;
    }

    /**
     * Set a {@link DnsDataSource} to be used by the DnsClient.
     * The default implementation will direct all queries directly to the Internet.
     *
     * This can be used to define a non-default handling for outgoing data. This can be useful to redirect the requests
     * to a proxy or to modify requests after or responses before they are handled by the DnsClient implementation.
     *
     * @param dataSource An implementation of DNSDataSource that shall be used.
     */
    public void setDataSource(DnsDataSource dataSource) {
        if (dataSource == null) {
            throw new IllegalArgumentException();
        }
        this.dataSource = dataSource;
    }

    /**
     * Get the cache used by this DNS client.
     *
     * @return the cached used by this DNS client or <code>null</code>.
     */
    public DnsCache getCache() {
        return cache;
    }

    protected DnsMessage getQueryFor(Question q) {
        DnsMessage.Builder messageBuilder = buildMessage(q);
        DnsMessage query = messageBuilder.build();
        return query;
    }

    private <D extends Data> Set<D> getCachedRecordsFor(DnsName dnsName, TYPE type) {
        if (cache == null)
            return Collections.emptySet();

        Question dnsNameNs = new Question(dnsName, type);
        DnsMessage queryDnsNameNs = getQueryFor(dnsNameNs);
        DnsQueryResult cachedResult = cache.get(queryDnsNameNs);

        if (cachedResult == null)
            return Collections.emptySet();

        return cachedResult.response.getAnswersFor(dnsNameNs);
    }

    public Set<NS> getCachedNameserverRecordsFor(DnsName dnsName) {
        return getCachedRecordsFor(dnsName, TYPE.NS);
    }

    public Set<A> getCachedIPv4AddressesFor(DnsName dnsName) {
        return getCachedRecordsFor(dnsName, TYPE.A);
    }

    public Set<AAAA> getCachedIPv6AddressesFor(DnsName dnsName) {
        return getCachedRecordsFor(dnsName, TYPE.AAAA);
    }

    @SuppressWarnings("unchecked")
    private <D extends Data> Set<D> getCachedIPNameserverAddressesFor(DnsName dnsName, TYPE type) {
        Set<NS> nsSet = getCachedNameserverRecordsFor(dnsName);
        if (nsSet.isEmpty())
            return Collections.emptySet();

        Set<D> res = new HashSet<>(3 * nsSet.size());
        for (NS ns : nsSet) {
            Set<D> addresses;
            switch (type) {
            case A:
                addresses = (Set<D>) getCachedIPv4AddressesFor(ns.target);
                break;
            case AAAA:
                addresses = (Set<D>) getCachedIPv6AddressesFor(ns.target);
                break;
            default:
                throw new AssertionError();
            }
            res.addAll(addresses);
        }

        return res;
    }

    public Set<A> getCachedIPv4NameserverAddressesFor(DnsName dnsName) {
        return getCachedIPNameserverAddressesFor(dnsName, TYPE.A);
    }

    public Set<AAAA> getCachedIPv6NameserverAddressesFor(DnsName dnsName) {
        return getCachedIPNameserverAddressesFor(dnsName, TYPE.AAAA);
    }
}
