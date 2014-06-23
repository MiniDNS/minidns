package de.measite.minidns;

import java.util.LinkedHashMap;
import java.util.Map.Entry;

/**
 * LRU based DNSCache backed by a LinkedHashMap.
 */
public class LRUCache implements DNSCache {

    /**
     * Internal miss count.
     */
    protected long missCount = 0l;

    /**
     * Internal expire count (subset of misses that was caused by expire).
     */
    protected long expireCount = 0l;

    /**
     * Internal hit count.
     */
    protected long hitCount = 0l;

    /**
     * The internal capacity of the backend cache.
     */
    protected int capacity;

    /**
     * The upper bound of the ttl. All longer TTLs will be capped by this ttl.
     */
    protected long maxTTL;

    /**
     * The backend cache.
     */
    protected LinkedHashMap<Question, DNSMessage> backend;

    /**
     * Create a new LRUCache with given capacity and upper bound ttl.
     * @param capacity The internal capacity.
     * @param maxTTL The upper bound for any ttl.
     */
    @SuppressWarnings("serial")
    public LRUCache(final int capacity, final long maxTTL) {
        this.capacity = capacity;
        this.maxTTL = maxTTL;
        backend = new LinkedHashMap<Question,DNSMessage>(
                Math.min(capacity + (capacity + 3) / 4 + 2, 11), 0.75f, true)
            {
                @Override
                protected boolean removeEldestEntry(
                        Entry<Question, DNSMessage> eldest) {
                    return size() > capacity;
                }
            };
    }

    /**
     * Create a new LRUCache with given capacity.
     * @param capacity The capacity of this cache.
     */
    public LRUCache(final int capacity) {
        this(capacity, Long.MAX_VALUE);
    }

    @Override
    public synchronized void put(Question q, DNSMessage message) {
        if (message.getReceiveTimestamp() <= 0l) {
            return;
        }
        backend.put(q, message);
    }

    @Override
    public synchronized DNSMessage get(Question q) {
        DNSMessage message = backend.get(q);
        if (message == null) {
            missCount++;
            return null;
        }

        long ttl = maxTTL;
        for (Record r : message.getAnswers()) {
            ttl = Math.min(ttl, r.ttl);
        }
        for (Record r : message.getAdditionalResourceRecords()) {
            ttl = Math.min(ttl, r.ttl);
        }
        if (message.getReceiveTimestamp() + ttl > System.currentTimeMillis()) {
            missCount++;
            expireCount++;
            backend.remove(q);
            return null;
        } else {
            hitCount++;
            return message;
        }
    }

    /**
     * Clear all entries in this cache.
     */
    public synchronized void clear() {
        backend.clear();
        missCount = 0l;
        hitCount = 0l;
        expireCount = 0l;
    }

    /**
     * Get the miss count of this cache which is the number of fruitless
     * get calls since this cache was last resetted.
     * @return The number of cache misses.
     */
    public long getMissCount() {
        return missCount;
    }

    /**
     * The number of expires (cache hits that have had a ttl to low to be
     * retrieved).
     * @return The expire count.
     */
    public long getExpireCount() {
        return expireCount;
    }

    /**
     * The cache hit count (all sucessful calls to get).
     * @return The hit count.
     */
    public long getHitCount() {
        return hitCount;
    }

}
