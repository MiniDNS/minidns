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
package de.measite.minidns;

import de.measite.minidns.Record.CLASS;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.cache.LRUCache;
import de.measite.minidns.source.DNSDataSource;
import de.measite.minidns.source.NetworkDataSource;

import java.io.IOException;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A minimal DNS client for SRV/A/AAAA/NS and CNAME lookups, with IDN support.
 * This circumvents the missing javax.naming package on android.
 */
public abstract class AbstractDNSClient {

    protected static final LRUCache DEFAULT_CACHE = new LRUCache(1024);

    protected static final Logger LOGGER = Logger.getLogger(AbstractDNSClient.class.getName());

    /**
     * The internal random class for sequence generation.
     */
    protected final Random random;

    protected final Random insecureRandom = new Random();

    /**
     * The internal DNS cache.
     */
    protected final DNSCache cache;

    protected DNSDataSource dataSource = new NetworkDataSource();

    /**
     * Create a new DNS client with the given DNS cache.
     *
     * @param cache The backend DNS cache.
     */
    protected AbstractDNSClient(DNSCache cache) {
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
    protected AbstractDNSClient() {
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
    public final DNSMessage query(String name, TYPE type, CLASS clazz) throws IOException {
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
    public final DNSMessage query(DNSName name, TYPE type) throws IOException {
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
    public final DNSMessage query(CharSequence name, TYPE type) throws IOException {
        Question q = new Question(name, type, CLASS.IN);
        return query(q);
    }

    /**
     * Query the system DNS server for one entry.
     *
     * @param q The question section of the DNS query.
     * @return The response (or null).
     * @throws IOException if an IO error occurs.
     */
    public abstract DNSMessage query(Question q) throws IOException;

    public DNSMessage query(Question q, InetAddress address, int port) throws IOException {
        // See if we have the answer to this question already cached
        DNSMessage dnsMessage = (cache == null) ? null : cache.get(q);
        if (dnsMessage != null) {
            return dnsMessage;
        }

        DNSMessage message = buildMessage(q);

        LOGGER.log(Level.FINE, "Asking {0} on {1} for {2}", new Object[] { address, port, q });
        dnsMessage = dataSource.query(message, address, port);

        if (dnsMessage == null) return null;

        if (cache != null && isResponseCacheable(q, dnsMessage)) {
            cache.put(q, dnsMessage);
        }
        return dnsMessage;
    }

    /**
     * Whether a response from the DNS system should be cached or not.
     *
     * @param q          The question the response message should answer.
     * @param dnsMessage The response message received using the DNS client.
     * @return True, if the response should be cached, false otherwise.
     */
    protected boolean isResponseCacheable(Question q, DNSMessage dnsMessage) {
        for (Record record : dnsMessage.getAnswers()) {
            if (record.isAnswer(q)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds a {@link DNSMessage} object carrying the given Question.
     *
     * @param question {@link Question} to be put in the DNS request.
     * @return A {@link DNSMessage} requesting the answer for the given Question.
     */
    final DNSMessage buildMessage(Question question) {
        DNSMessage message = new DNSMessage();
        message.setQuestions(question);
        message.setId(random.nextInt());
        message = newQuestion(message);
        return message;
    }

    protected abstract DNSMessage newQuestion(DNSMessage questionMessage);

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
    public DNSMessage query(String name, TYPE type, CLASS clazz, InetAddress address, int port)
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
    public DNSMessage query(String name, TYPE type, CLASS clazz, InetAddress address)
            throws IOException {
        Question q = new Question(name, type, clazz);
        return query(q, address);
    }

    /**
     * Query a specific server for one entry.
     *
     * @param q    The question section of the DNS query.
     * @param host The dns server host.
     * @return The response (or null on timeout/error).
     * @throws IOException On IOErrors.
     */
    public DNSMessage query(Question q, String host) throws IOException {
        InetAddress hostAddress = InetAddress.getByName(host);
        return query(q, hostAddress, 53);
    }

    /**
     * Query a specific server for one entry.
     *
     * @param q       The question section of the DNS query.
     * @param address The dns server address.
     * @return The response (or null on timeout/error).
     * @throws IOException On IOErrors.
     */
    public DNSMessage query(Question q, InetAddress address) throws IOException {
        return query(q, address, 53);
    }

    /**
     * Returns the currently used {@link DNSDataSource}. See {@link #setDataSource(DNSDataSource)} for details.
     *
     * @return The currently used {@link DNSDataSource}
     */
    public DNSDataSource getDataSource() {
        return dataSource;
    }

    /**
     * Set a {@link DNSDataSource} to be used by the DNSClient.
     * The default implementation will direct all queries directly to the Internet.
     *
     * This can be used to define a non-default handling for outgoing data. This can be useful to redirect the requests
     * to a proxy or to modify requests after or responses before they are handled by the DNSClient implementation.
     *
     * @param dataSource An implementation of DNSDataSource that shall be used.
     */
    public void setDataSource(DNSDataSource dataSource) {
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
    public DNSCache getCache() {
        return cache;
    }
}
