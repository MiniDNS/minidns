/*
 * Copyright 2015-2018 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns;

import org.junit.Before;
import org.junit.Test;

import org.minidns.cache.LruCache;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.record.Record;

import static org.minidns.DnsWorld.a;
import static org.minidns.DnsWorld.ns;
import static org.minidns.DnsWorld.record;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class LruCacheTest {
    private LruCache lruCache;

    @Before
    public void setUp() throws Exception {
        lruCache = new LruCache(5);
    }

    @Test
    public void testOutdatedCacheEntry() {
        DnsMessage message = createSampleMessage(1);
        Question q = new Question("", Record.TYPE.A);
        DnsMessage question = q.asQueryMessage();
        lruCache.put(question, message);

        assertNull(lruCache.get(question));
        assertNull(lruCache.get(question));
        assertEquals(1, lruCache.getExpireCount());
        assertEquals(2, lruCache.getMissCount());
    }

    @Test
    public void testOverfilledCache() {
        Question q = new Question("", Record.TYPE.A);
        DnsMessage question = q.asQueryMessage();
        lruCache.put(question, createSampleMessage());
        assertNotNull(lruCache.get(question));
        lruCache.put(new Question("1", Record.TYPE.A).asQueryMessage(), createSampleMessage());
        lruCache.put(new Question("2", Record.TYPE.A).asQueryMessage(), createSampleMessage());
        lruCache.put(new Question("3", Record.TYPE.A).asQueryMessage(), createSampleMessage());
        lruCache.put(new Question("4", Record.TYPE.A).asQueryMessage(), createSampleMessage());
        lruCache.put(new Question("5", Record.TYPE.A).asQueryMessage(), createSampleMessage());

        assertNull(lruCache.get(question));
        assertEquals(0, lruCache.getExpireCount());
        assertEquals(1, lruCache.getMissCount());
        assertEquals(1, lruCache.getHitCount());
    }

    private static DnsMessage createSampleMessage() {
        return createSampleMessage(System.currentTimeMillis());
    }

    private static DnsMessage createSampleMessage(long receiveTimestamp) {
        DnsMessage.Builder message = DnsMessage.builder();
        message.setReceiveTimestamp(receiveTimestamp);
        message.addAnswer(record("", ns("a.root-servers.net")));
        message.addAdditionalResourceRecord(record("a.root-servers.net", a("127.0.0.1")));
        return message.build();
    }
}
