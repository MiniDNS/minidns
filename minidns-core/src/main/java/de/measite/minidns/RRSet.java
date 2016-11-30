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
package de.measite.minidns;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import de.measite.minidns.Record.CLASS;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.record.Data;

public class RRSet {

    public final DNSName name;
    public final TYPE type;
    public final CLASS clazz;
    public final Set<Record<? extends Data>> records;

    private RRSet(DNSName name, TYPE type, CLASS clazz, Set<Record<? extends Data>> records) {
        this.name = name;
        this.type = type;
        this.clazz = clazz;
        this.records = Collections.unmodifiableSet(records);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private DNSName name;
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
            } else {
                // Verify that the to be added record suits into the already existing ones.
                if (!name.equals(record.name) || type != record.type || clazz != record.clazz) {
                    throw new IllegalArgumentException();
                }
            }

            boolean didNotExist = records.add(record);
            assert (didNotExist);

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

        public RRSet build() {
            if (name == null) {
                // There is no RR added to this builder.
                throw new IllegalStateException();
            }
            return new RRSet(name, type, clazz, records);
        }
    }
}
