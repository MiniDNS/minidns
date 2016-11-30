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

import de.measite.minidns.DNSName;
import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.record.Data;

/**
 * An <b>insecure</b> variant of {@link LRUCache} also using all the data found in the sections of an answer.
 */
public class FullLRUCache extends ExtendedLRUCache {

    public FullLRUCache(int capacity) {
        super(capacity);
    }

    public FullLRUCache(int capacity, long maxTTL) {
        super(capacity, maxTTL);
    }

    @Override
    protected boolean shouldGather(Record<? extends Data> extraRecord, Question question, DNSName authoritativeZone) {
        return true;
    }
}
