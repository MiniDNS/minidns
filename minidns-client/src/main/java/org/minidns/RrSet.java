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
package org.minidns;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import org.minidns.dnsname.DnsName;
import org.minidns.record.Data;
import org.minidns.record.Record;
import org.minidns.record.Record.CLASS;
import org.minidns.record.Record.TYPE;

public final class RrSet {

    public final DnsName name;
    public final TYPE type;
    public final CLASS clazz;
    public final Set<Record<? extends Data>> records;

    private RrSet(DnsName name, TYPE type, CLASS clazz, Set<Record<? extends Data>> records) {
        this.name = name;
        this.type = type;
        this.clazz = clazz;
        this.records = Collections.unmodifiableSet(records);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append('\t').append(clazz).append('\t').append(type).append('\n');
        for (Record<?> record : records) {
            sb.append(record).append('\n');
        }
        return sb.toString();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private DnsName name;
        private TYPE type;
        private CLASS clazz;
        Set<Record<? extends Data>> records = new LinkedHashSet<>(8);

        private Builder() {
        }

        public Builder addRecord(Record<? extends Data> record) {
            if (name == null) {
                name = record.name;
                type = record.type;
                clazz = record.clazz;
            } else if (!couldContain(record)) {
                throw new IllegalArgumentException(
                        "Can not add " + record + " to RRSet " + name + ' ' + type + ' ' + clazz);
            }

            boolean didNotExist = records.add(record);
            assert didNotExist;

            return this;
        }

        public boolean couldContain(Record<? extends Data> record) {
            if (name == null) {
                return true;
            }
            return name.equals(record.name) && type == record.type && clazz == record.clazz;
        }

        public boolean addIfPossible(Record<? extends Data> record) {
            if (!couldContain(record)) {
                return false;
            }
            addRecord(record);
            return true;
        }

        public RrSet build() {
            if (name == null) {
                // There is no RR added to this builder.
                throw new IllegalStateException();
            }
            return new RrSet(name, type, clazz, records);
        }
    }
}
