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
package org.minidns.hla;

import org.minidns.MiniDnsException;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsmessage.DnsMessage.RESPONSE_CODE;

public class ResolutionUnsuccessfulException extends MiniDnsException {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    public final Question question;
    public final RESPONSE_CODE responseCode;

    public ResolutionUnsuccessfulException(Question question, RESPONSE_CODE responseCode) {
        super("Asking for " + question + " yielded an error response " + responseCode);
        this.question = question;
        this.responseCode = responseCode;
    }
}
