/*
 * Copyright 2015-2016 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns;

/**
 * Cache for DNS Entries. Implementations must be thread safe.
 */
public abstract class DNSCache {

    /**
     * Add an an dns answer/response for a given dns question. Implementations
     * should honor the ttl / receive timestamp.
     * @param query The query message containing a question.
     * @param message The dns message.
     */
    public final void put(DNSMessage query, DNSMessage message) {
        putNormalized(query.asNormalizedVersion(), message);
    }

    protected abstract void putNormalized(DNSMessage normalizedQuery, DNSMessage reply);

    public abstract void offer(DNSMessage query, DNSMessage reply, DNSName authoritativeZone);

    /**
     * Request a cached dns response.
     * @param query The query message containing a question.
     * @return The dns message.
     */
    public final DNSMessage get(DNSMessage query) {
        return getNormalized(query.asNormalizedVersion());
    }

    protected abstract DNSMessage getNormalized(DNSMessage normalizedQuery);

}
