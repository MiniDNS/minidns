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
package de.measite.minidns.dnssec;

import java.util.Collections;
import java.util.Set;

import de.measite.minidns.MiniDNSException;

public class DNSSECResultNotAuthenticException extends MiniDNSException {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    private final Set<UnverifiedReason> unverifiedReasons;

    private DNSSECResultNotAuthenticException(String message, Set<UnverifiedReason> unverifiedReasons) {
        super(message);
        if (unverifiedReasons.isEmpty()) {
            throw new IllegalArgumentException();
        }
        this.unverifiedReasons = Collections.unmodifiableSet(unverifiedReasons);
    }

    public static DNSSECResultNotAuthenticException from(Set<UnverifiedReason> unverifiedReasons) {
        StringBuilder sb = new StringBuilder();
        sb.append("DNSSEC result not authentic. Reasons: ");
        for (UnverifiedReason reason : unverifiedReasons) {
            sb.append(reason).append('.');
        }

        return new DNSSECResultNotAuthenticException(sb.toString(), unverifiedReasons);
    }

    public Set<UnverifiedReason> getUnverifiedReasons() {
        return unverifiedReasons;
    }
}
