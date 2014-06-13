package de.measite.minidns;

/**
 * Cache for DNS Entries. Implementations must be thread safe.
 */
public interface DNSCache {

    void put(Question q, DNSMessage message);

    DNSMessage get(Question q);

}
