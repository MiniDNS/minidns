/*
 * Copyright 2015-2024 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.cache;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsname.DnsName;
import org.minidns.dnsqueryresult.CachedDnsQueryResult;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.dnsqueryresult.SynthesizedCachedDnsQueryResult;
import org.minidns.record.Data;
import org.minidns.record.Record;

/**
 * A variant of {@link LruCache} also using the data found in the sections for caching.
 */
public class ExtendedLruCache extends LruCache {

    public ExtendedLruCache() {
        this(DEFAULT_CACHE_SIZE);
    }

    public ExtendedLruCache(int capacity) {
        super(capacity);
    }

    public ExtendedLruCache(int capacity, long maxTTL) {
        super(capacity, maxTTL);
    }

    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    @Override
    protected void putNormalized(DnsMessage q, DnsQueryResult result) {
        super.putNormalized(q, result);
        DnsMessage message = result.response;
        Map<DnsMessage, List<Record<? extends Data>>> extraCaches = new HashMap<>(message.additionalSection.size());

        gather(extraCaches, q, message.answerSection, null);
        gather(extraCaches, q, message.authoritySection, null);
        gather(extraCaches, q, message.additionalSection, null);

        putExtraCaches(result, extraCaches);
    }

    @Override
    public void offer(DnsMessage query, DnsQueryResult result, DnsName authoritativeZone) {
        DnsMessage reply = result.response;
        // The reply shouldn't be an authoritative answers when offer() is used. That would be a case for put().
        assert !reply.authoritativeAnswer;

        Map<DnsMessage, List<Record<? extends Data>>> extraCaches = new HashMap<>(reply.additionalSection.size());

        // N.B. not gathering from reply.answerSection here. Since it is a non authoritativeAnswer it shouldn't contain anything.
        gather(extraCaches, query, reply.authoritySection, authoritativeZone);
        gather(extraCaches, query, reply.additionalSection, authoritativeZone);

        putExtraCaches(result, extraCaches);
    }

    private void gather(Map<DnsMessage, List<Record<?extends Data>>> extraCaches, DnsMessage q, List<Record<? extends Data>> records, DnsName authoritativeZone) {
        for (Record<? extends Data> extraRecord : records) {
            if (!shouldGather(extraRecord, q.getQuestion(), authoritativeZone))
                continue;

            DnsMessage.Builder additionalRecordQuestionBuilder = extraRecord.getQuestionMessage();
            if (additionalRecordQuestionBuilder == null)
                continue;

            additionalRecordQuestionBuilder.copyFlagsFrom(q);

            additionalRecordQuestionBuilder.setAdditionalResourceRecords(q.additionalSection);

            DnsMessage additionalRecordQuestion = additionalRecordQuestionBuilder.build();
            if (additionalRecordQuestion.equals(q)) {
                // No need to cache the additional question if it is the same as the original question.
                continue;
            }

            List<Record<? extends Data>> additionalRecords = extraCaches.get(additionalRecordQuestion);
            if (additionalRecords == null) {
                 additionalRecords = new ArrayList<>();
                 extraCaches.put(additionalRecordQuestion, additionalRecords);
            }
            additionalRecords.add(extraRecord);
        }
    }

    private void putExtraCaches(DnsQueryResult synthesynthesizationSource, Map<DnsMessage, List<Record<? extends Data>>> extraCaches) {
        DnsMessage reply = synthesynthesizationSource.response;
        for (Entry<DnsMessage, List<Record<? extends Data>>> entry : extraCaches.entrySet()) {
            DnsMessage question = entry.getKey();
            DnsMessage answer = reply.asBuilder()
                    .setQuestion(question.getQuestion())
                    .setAuthoritativeAnswer(true)
                    .addAnswers(entry.getValue())
                    .build();
            CachedDnsQueryResult cachedDnsQueryResult = new SynthesizedCachedDnsQueryResult(question, answer, synthesynthesizationSource);
            synchronized (this) {
                backend.put(question, cachedDnsQueryResult);
            }
        }
    }

    protected boolean shouldGather(Record<? extends Data> extraRecord, Question question, DnsName authoritativeZone) {
        boolean extraRecordIsChildOfQuestion = extraRecord.name.isChildOf(question.name);

        boolean extraRecordIsChildOfAuthoritativeZone = false;
        if (authoritativeZone != null) {
            extraRecordIsChildOfAuthoritativeZone = extraRecord.name.isChildOf(authoritativeZone);
        }

        return extraRecordIsChildOfQuestion || extraRecordIsChildOfAuthoritativeZone;
    }

}
