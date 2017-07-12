/*
 * Copyright 2015-2017 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.hla;

import java.util.Collections;
import java.util.Set;

import de.measite.minidns.DNSMessage;
import de.measite.minidns.DNSMessage.RESPONSE_CODE;
import de.measite.minidns.MiniDNSException;
import de.measite.minidns.MiniDNSException.NullResultException;
import de.measite.minidns.Question;
import de.measite.minidns.dnssec.DNSSECResultNotAuthenticException;
import de.measite.minidns.dnssec.UnverifiedReason;
import de.measite.minidns.record.Data;

public class ResolverResult<D extends Data> {

    protected final Question question;
    private final RESPONSE_CODE responseCode;
    private final Set<D> data;
    private final boolean isAuthenticData;
    protected final Set<UnverifiedReason> unverifiedReasons;
    protected final DNSMessage answer;

    ResolverResult(Question question , DNSMessage answer, Set<UnverifiedReason> unverifiedReasons) throws NullResultException {
        if (answer == null) {
            throw new MiniDNSException.NullResultException(question.asMessageBuilder().build());
        }

        this.question = question;
        this.responseCode = answer.responseCode;
        this.answer = answer;

        Set<D> r = answer.getAnswersFor(question);
        if (r == null) {
            this.data = Collections.emptySet();
        } else {
            this.data = Collections.unmodifiableSet(r);
        }

        if (unverifiedReasons == null) {
            this.unverifiedReasons = null;
            isAuthenticData = false;
        } else {
            this.unverifiedReasons = Collections.unmodifiableSet(unverifiedReasons);
            isAuthenticData = this.unverifiedReasons.isEmpty();
        }
    }

    public boolean wasSuccessful() {
        return responseCode == RESPONSE_CODE.NO_ERROR;
    }

    public Set<D> getAnswers() {
        throwIseIfErrorResponse();
        return data;
    }

    public Set<D> getAnswersOrEmptySet() {
        return data;
    }

    public RESPONSE_CODE getResponseCode() {
        return responseCode;
    }

    public boolean isAuthenticData() {
        throwIseIfErrorResponse();
        return isAuthenticData;
    }

    /**
     * Get the reasons the result could not be verified if any exists.
     *
     * @return The reasons the result could not be verified or <code>null</code>.
     */
    public Set<UnverifiedReason> getUnverifiedReasons() {
        throwIseIfErrorResponse();
        return unverifiedReasons;
    }

    public Question getQuestion() {
        return question;
    }

    public void throwIfErrorResponse() throws ResolutionUnsuccessfulException {
        ResolutionUnsuccessfulException resolutionUnsuccessfulException = getResolutionUnsuccessfulException();
        if (resolutionUnsuccessfulException != null) throw resolutionUnsuccessfulException;
    }

    private ResolutionUnsuccessfulException resolutionUnsuccessfulException;

    public ResolutionUnsuccessfulException getResolutionUnsuccessfulException() {
        if (wasSuccessful()) return null;

        if (resolutionUnsuccessfulException == null) {
            resolutionUnsuccessfulException = new ResolutionUnsuccessfulException(question, responseCode);
        }

        return resolutionUnsuccessfulException;
    }

    private DNSSECResultNotAuthenticException dnssecResultNotAuthenticException;

    public DNSSECResultNotAuthenticException getDnssecResultNotAuthenticException() {
        if (!wasSuccessful())
            return null;
        if (isAuthenticData)
            return null;

        if (dnssecResultNotAuthenticException == null) {
            dnssecResultNotAuthenticException = DNSSECResultNotAuthenticException.from(getUnverifiedReasons());
        }

        return dnssecResultNotAuthenticException;
    }

    /**
     * Get the raw answer DNS message we received. <b>This is likely not what you want</b>, try {@link #getAnswers()} instead.
     *
     * @return the raw answer DNS Message.
     * @see #getAnswers()
     */
    public DNSMessage getRawAnswer() {
        return answer;
    }

    @Override
    public final String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append(getClass().getName()).append('\n')
               .append("Question: ").append(question).append('\n')
               .append("Response Code: ").append(responseCode).append('\n');

        if (responseCode == RESPONSE_CODE.NO_ERROR) {
            if (isAuthenticData) {
                sb.append("Results verified via DNSSEC\n");
            }
            if (hasUnverifiedReasons()) {
                sb.append(unverifiedReasons).append('\n');
            }
            sb.append(answer.answerSection);
        }

        return sb.toString();
    }

    boolean hasUnverifiedReasons() {
        return unverifiedReasons != null && !unverifiedReasons.isEmpty();
    }

    protected void throwIseIfErrorResponse() {
        ResolutionUnsuccessfulException resolutionUnsuccessfulException = getResolutionUnsuccessfulException();
        if (resolutionUnsuccessfulException != null)
            throw new IllegalStateException("Can not perform operation because the DNS resolution was unsuccessful",
                    resolutionUnsuccessfulException);
    }
}
