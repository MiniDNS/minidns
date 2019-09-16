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

import org.junit.jupiter.api.Test;

import org.minidns.cache.LruCache;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsqueryresult.TestWorldDnsQueryResult;
import org.minidns.record.Record;

import static org.minidns.DnsWorld.a;
import static org.minidns.DnsWorld.ns;
import static org.minidns.DnsWorld.record;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class LruCacheTest {

    @Test
    public void testOutdatedCacheEntry() {
        LruCache lruCache = new LruCache(5);

        Question q = new Question("", Record.TYPE.A);
        TestWorldDnsQueryResult result = createSampleMessage(q, 1);
        DnsMessage question = q.asQueryMessage();
        lruCache.put(question, result);

        assertNull(lruCache.get(question));
        assertNull(lruCache.get(question));
        assertEquals(1, lruCache.getExpireCount());
        assertEquals(2, lruCache.getMissCount());
    }

    @Test
    public void testOverfilledCache() {
        LruCache lruCache = new LruCache(5);

        Question firstQuestion = new Question("", Record.TYPE.A);
        lruCache.put(firstQuestion.asQueryMessage(), createSampleMessage(firstQuestion));
        assertNotNull(lruCache.get(firstQuestion.asQueryMessage()));

        Question question;
        question = new Question("1", Record.TYPE.A);
        lruCache.put(question.asQueryMessage(), createSampleMessage(question));
        question = new Question("2", Record.TYPE.A);
        lruCache.put(question.asQueryMessage(), createSampleMessage(question));
        question = new Question("3", Record.TYPE.A);
        lruCache.put(question.asQueryMessage(), createSampleMessage(question));
        question = new Question("4", Record.TYPE.A);
        lruCache.put(question.asQueryMessage(), createSampleMessage(question));
        question = new Question("5", Record.TYPE.A);
        lruCache.put(question.asQueryMessage(), createSampleMessage(question));

        assertNull(lruCache.get(firstQuestion.asQueryMessage()));
        assertEquals(0, lruCache.getExpireCount());
        assertEquals(1, lruCache.getMissCount());
        assertEquals(1, lruCache.getHitCount());
    }

    private static TestWorldDnsQueryResult createSampleMessage(Question question) {
        return createSampleMessage(question, System.currentTimeMillis());
    }

    private static TestWorldDnsQueryResult createSampleMessage(Question question, long receiveTimestamp) {
        DnsMessage.Builder message = DnsMessage.builder();
        message.setReceiveTimestamp(receiveTimestamp);
        message.addAnswer(record("", ns("a.root-servers.net")));
        message.addAdditionalResourceRecord(record("a.root-servers.net", a("127.0.0.1")));
        DnsMessage responseMessage = message.build();
        DnsMessage query = question.asQueryMessage();
        return new TestWorldDnsQueryResult(query, responseMessage);
    }
}
