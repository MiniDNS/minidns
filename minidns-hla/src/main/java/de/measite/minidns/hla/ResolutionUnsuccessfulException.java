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
package de.measite.minidns.hla;

import de.measite.minidns.DNSMessage.RESPONSE_CODE;
import de.measite.minidns.MiniDNSException;
import de.measite.minidns.Question;

public class ResolutionUnsuccessfulException extends MiniDNSException {

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
