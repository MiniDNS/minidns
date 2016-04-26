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
import de.measite.minidns.Question;
import de.measite.minidns.Record;

/**
 * A variant of {@link LRUCache} also using the data found in the sections for caching.
 */
public class ExtendedLRUCache extends LRUCache {

    public ExtendedLRUCache(int capacity) {
        super(capacity);
    }

    public ExtendedLRUCache(int capacity, long maxTTL) {
        super(capacity, maxTTL);
    }

    @Override
    public void put(Question q, DNSMessage message) {
        super.put(q, message);

        Map<Question, List<Record>> extraCaches = new HashMap<>(message.getAdditionalResourceRecords().length);

        gather(extraCaches, q, message.getAnswers());
        gather(extraCaches, q, message.getNameserverRecords());
        gather(extraCaches, q, message.getAdditionalResourceRecords());

        for (Entry<Question, List<Record>> entry : extraCaches.entrySet()) {
            Record[] answerRecords = new Record[entry.getValue().size()];
            entry.getValue().toArray(answerRecords);
            DNSMessage answer = new DNSMessage(message, answerRecords, null, null);
            Question question = entry.getKey();
            super.put(question, answer);
        }
    }

    private final void gather(Map<Question, List<Record>> extraCaches, Question q, Record[] records) {
        for (Record extraRecord : records) {
            if (!shouldGather(extraRecord, q))
                continue;

            Question additionalRecordQuestion = extraRecord.getQuestion();
            if (additionalRecordQuestion == null)
                continue;

            if (additionalRecordQuestion.equals(q)) {
                // No need to cache the additional question if it is the same as the original question.
                continue;
            }

            List<Record> additionalRecords = extraCaches.get(additionalRecordQuestion);
            if (additionalRecords == null) {
                 additionalRecords = new LinkedList<>();
                 extraCaches.put(additionalRecordQuestion, additionalRecords);
            }
            additionalRecords.add(extraRecord);
        }
    }

    protected boolean shouldGather(Record extraRecord, Question question) {
        return extraRecord.name.isChildOf(question.name);
    }
}
