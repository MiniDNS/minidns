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

import org.junit.Before;
import org.junit.Test;

import static de.measite.minidns.DNSWorld.a;
import static de.measite.minidns.DNSWorld.ns;
import static de.measite.minidns.DNSWorld.record;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class LRUCacheTest {
    private LRUCache lruCache;

    @Before
    public void setUp() throws Exception {
        lruCache = new LRUCache(5);
    }

    @Test
    public void testOutdatedCacheEntry() {
        DNSMessage message = createSampleMessage();
        message.receiveTimestamp = 1;
        Question question = new Question("", Record.TYPE.A);
        lruCache.put(question, message);

        assertNull(lruCache.get(question));
        assertNull(lruCache.get(question));
        assertEquals(1, lruCache.getExpireCount());
        assertEquals(2, lruCache.getMissCount());
    }

    @Test
    public void testOverfilledCache() {
        Question question = new Question("", Record.TYPE.A);
        lruCache.put(question, createSampleMessage());
        assertNotNull(lruCache.get(question));
        lruCache.put(new Question("1", Record.TYPE.A), createSampleMessage());
        lruCache.put(new Question("2", Record.TYPE.A), createSampleMessage());
        lruCache.put(new Question("3", Record.TYPE.A), createSampleMessage());
        lruCache.put(new Question("4", Record.TYPE.A), createSampleMessage());
        lruCache.put(new Question("5", Record.TYPE.A), createSampleMessage());

        assertNull(lruCache.get(question));
        assertEquals(0, lruCache.getExpireCount());
        assertEquals(1, lruCache.getMissCount());
        assertEquals(1, lruCache.getHitCount());
    }

    private DNSMessage createSampleMessage() {
        DNSMessage message = new DNSMessage();
        message.receiveTimestamp = System.currentTimeMillis();
        message.answers = new Record[]{record("", ns("a.root-servers.net"))};
        message.additionalResourceRecords = new Record[]{record("a.root-servers.net", a("127.0.0.1"))};
        return message;
    }
}
