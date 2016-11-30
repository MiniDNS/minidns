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
package de.measite.minidns.cache;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import de.measite.minidns.DNSMessage;
import de.measite.minidns.DNSName;
import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.record.Data;

/**
 * A variant of {@link LRUCache} also using the data found in the sections for caching.
 */
public class ExtendedLRUCache extends LRUCache {

    public ExtendedLRUCache() {
        this(1024);
    }

    public ExtendedLRUCache(int capacity) {
        super(capacity);
    }

    public ExtendedLRUCache(int capacity, long maxTTL) {
        super(capacity, maxTTL);
    }

    @Override
    protected void putNormalized(DNSMessage q, DNSMessage message) {
        super.putNormalized(q, message);
        Map<DNSMessage, List<Record<? extends Data>>> extraCaches = new HashMap<>(message.additionalSection.size());

        gather(extraCaches, q, message.answerSection, null);
        gather(extraCaches, q, message.authoritySection, null);
        gather(extraCaches, q, message.additionalSection, null);

        putExtraCaches(message, extraCaches);
    }

    @Override
    public void offer(DNSMessage query, DNSMessage reply, DNSName authoritativeZone) {
        // The reply shouldn't be an authoritative answers when offer() is used. That would be a case for put().
        assert(!reply.authoritativeAnswer);

        Map<DNSMessage, List<Record<? extends Data>>> extraCaches = new HashMap<>(reply.additionalSection.size());

        // N.B. not gathering from reply.answerSection here. Since it is a non authoritativeAnswer it shouldn't contain anything.
        gather(extraCaches, query, reply.authoritySection, authoritativeZone);
        gather(extraCaches, query, reply.additionalSection, authoritativeZone);

        putExtraCaches(reply, extraCaches);
    }

    private final void gather(Map<DNSMessage, List<Record<?extends Data>>> extraCaches, DNSMessage q, List<Record<? extends Data>> records, DNSName authoritativeZone) {
        for (Record<? extends Data> extraRecord : records) {
            if (!shouldGather(extraRecord, q.getQuestion(), authoritativeZone))
                continue;

            DNSMessage.Builder additionalRecordQuestionBuilder = extraRecord.getQuestionMessage();
            if (additionalRecordQuestionBuilder == null)
                continue;

            additionalRecordQuestionBuilder.copyFlagsFrom(q);

            additionalRecordQuestionBuilder.setAdditionalResourceRecords(q.additionalSection);

            DNSMessage additionalRecordQuestion = additionalRecordQuestionBuilder.build();
            if (additionalRecordQuestion.equals(q)) {
                // No need to cache the additional question if it is the same as the original question.
                continue;
            }

            List<Record<? extends Data>> additionalRecords = extraCaches.get(additionalRecordQuestion);
            if (additionalRecords == null) {
                 additionalRecords = new LinkedList<>();
                 extraCaches.put(additionalRecordQuestion, additionalRecords);
            }
            additionalRecords.add(extraRecord);
        }
    }

    private final void putExtraCaches(DNSMessage reply, Map<DNSMessage, List<Record<? extends Data>>> extraCaches) {
        for (Entry<DNSMessage, List<Record<? extends Data>>> entry : extraCaches.entrySet()) {
            DNSMessage question = entry.getKey();
            DNSMessage answer = reply.asBuilder()
                    .setQuestion(question.getQuestion())
                    .setAuthoritativeAnswer(true)
                    .addAnswers(entry.getValue())
                    .build();
            super.putNormalized(question, answer);
        }
    }

    protected boolean shouldGather(Record<? extends Data> extraRecord, Question question, DNSName authoritativeZone) {
        boolean extraRecordIsChildOfQuestion = extraRecord.name.isChildOf(question.name);

        boolean extraRecordIsChildOfAuthoritativeZone = false;
        if (authoritativeZone != null) {
            extraRecordIsChildOfAuthoritativeZone = extraRecord.name.isChildOf(authoritativeZone);
        }

        return extraRecordIsChildOfQuestion || extraRecordIsChildOfAuthoritativeZone;
    }

}
