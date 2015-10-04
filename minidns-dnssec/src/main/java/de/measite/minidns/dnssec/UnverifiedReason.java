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
package de.measite.minidns.dnssec;

import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.record.DS;

public abstract class UnverifiedReason {
    public abstract String getReasonString();

    @Override
    public String toString() {
        return getReasonString();
    }

    @Override
    public int hashCode() {
        return getReasonString().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof UnverifiedReason && ((UnverifiedReason) obj).getReasonString().equals(getReasonString());
    }

    public static class AlgorithmNotSupportedReason extends UnverifiedReason {
        private final String algorithm;
        private final String kind;
        private final Record record;

        public AlgorithmNotSupportedReason(String algorithm, String kind, Record record) {
            this.algorithm = algorithm;
            this.kind = kind;
            this.record = record;
        }

        @Override
        public String getReasonString() {
            return kind + " algorithm " + algorithm + " required to verify " + record.name + " is unknown or not supported by platform";
        }
    }

    public static class AlgorithmExceptionThrownReason extends UnverifiedReason {
        private final int algorithmNumber;
        private final String kind;
        private final Exception reason;
        private final Record record;

        public AlgorithmExceptionThrownReason(int algorithmNumber, String kind, Record record, Exception reason) {
            this.algorithmNumber = algorithmNumber;
            this.kind = kind;
            this.record = record;
            this.reason = reason;
        }

        @Override
        public String getReasonString() {
            return kind + " algorithm " + algorithmNumber + " threw exception while verifying " + record.name + ": " + reason;
        }
    }

    public static class IncomptibleDelegationReason extends UnverifiedReason {
        private final DS delegation;
        private final Record record;

        public IncomptibleDelegationReason(DS ds, Record record) {
            this.delegation = ds;
            this.record = record;
        }

        @Override
        public String getReasonString() {
            return "Prefetched delegation " + delegation + " is invalid for " + record.type + " at " +record.name;
        }
    }

    public static class NoTrustAnchorReason extends UnverifiedReason {
        private final String zone;

        public NoTrustAnchorReason(String zone) {
            this.zone = zone;
        }

        @Override
        public String getReasonString() {
            return "No trust anchor was found for zone " + zone + ". Try enabling DLV";
        }
    }

    public static class NoSecureEntryPointReason extends UnverifiedReason {
        private String zone;

        public NoSecureEntryPointReason(String zone) {
            this.zone = zone;
        }

        @Override
        public String getReasonString() {
            return "No secure entry point was found for zone " + zone;
        }
    }

    public static class NoSignaturesReason extends UnverifiedReason {
        private Question question;

        public NoSignaturesReason(Question question) {
            this.question = question;
        }

        @Override
        public String getReasonString() {
            return "No (currently active) signatures were attached to answer on question for " + question.type + " at " + question.name;
        }
    }

    public static class NSECDoesNotMatchReason extends UnverifiedReason {
        private final Question question;
        private final Record record;

        public NSECDoesNotMatchReason(Question question, Record record) {
            this.question = question;
            this.record = record;
        }

        @Override
        public String getReasonString() {
            return "NSEC " + record.name + " does nat match question for " + question.type + " at " + question.name;
        }
    }
}
