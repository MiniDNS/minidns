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
