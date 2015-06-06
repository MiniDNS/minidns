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

/**
 * Cache for DNS Entries. Implementations must be thread safe.
 */
public interface DNSCache {

    /**
     * Add an an dns answer/response for a given dns question. Implementations
     * should honor the ttl / receive timestamp.
     * @param q The question.
     * @param message The dns message.
     */
    void put(Question q, DNSMessage message);

    /**
     * Request a cached dns response.
     * @param q The dns question.
     * @return The dns message.
     */
    DNSMessage get(Question q);

}
