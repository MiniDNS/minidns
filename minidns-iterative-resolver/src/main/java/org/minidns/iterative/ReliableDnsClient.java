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
package org.minidns.iterative;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import org.minidns.AbstractDnsClient;
import org.minidns.DnsCache;
import org.minidns.DnsClient;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.source.DnsDataSource;
import org.minidns.util.MultipleIoException;

/**
 * A DNS client using a reliable strategy. First the configured resolver of the
 * system are used, then, in case there is no answer, a fall back to iterative
 * resolving is performed.
 */
public class ReliableDnsClient extends AbstractDnsClient {

    public enum Mode {
        /**
         * Try the recursive servers first and fallback to iterative resolving if it fails. This is the default mode.
         */
        recursiveWithIterativeFallback,

        /**
         * Only try the recursive servers. This makes {@code ReliableDnsClient} behave like a {@link DnsClient}.
         */
        recursiveOnly,

        /**
         * Only use iterative resolving.  This makes {@code ReliableDnsClient} behave like a {@link IterativeDnsClient}.
         */
        iterativeOnly,
    }

    private final IterativeDnsClient recursiveDnsClient;
    private final DnsClient dnsClient;

    private Mode mode = Mode.recursiveWithIterativeFallback;

    public ReliableDnsClient(DnsCache dnsCache) {
        super(dnsCache);
        recursiveDnsClient = new IterativeDnsClient(dnsCache) {
            @Override
            protected DnsMessage.Builder newQuestion(DnsMessage.Builder questionMessage) {
                questionMessage = super.newQuestion(questionMessage);
                return ReliableDnsClient.this.newQuestion(questionMessage);
            }
            // TODO: Rename dnsMessage to result.
            @Override
            protected boolean isResponseCacheable(Question q, DnsQueryResult dnsMessage) {
                boolean res = super.isResponseCacheable(q, dnsMessage);
                return ReliableDnsClient.this.isResponseCacheable(q, dnsMessage) && res;
            }
        };
        dnsClient = new DnsClient(dnsCache) {
            @Override
            protected DnsMessage.Builder newQuestion(DnsMessage.Builder questionMessage) {
                questionMessage = super.newQuestion(questionMessage);
                return ReliableDnsClient.this.newQuestion(questionMessage);
            }
            // TODO: Rename dnsMessage to result.
            @Override
            protected boolean isResponseCacheable(Question q, DnsQueryResult dnsMessage) {
                boolean res = super.isResponseCacheable(q, dnsMessage);
                return ReliableDnsClient.this.isResponseCacheable(q, dnsMessage) && res;
            }
        };
    }

    public ReliableDnsClient() {
        this(DEFAULT_CACHE);
    }

    @Override
    protected DnsQueryResult query(DnsMessage.Builder q) throws IOException {
        DnsQueryResult dnsMessage = null;
        String unacceptableReason = null;
        List<IOException> ioExceptions = new ArrayList<>();

        if (mode != Mode.iterativeOnly) {
            // Try a recursive query.
            try {
                dnsMessage = dnsClient.query(q);
                if (dnsMessage != null) {
                    unacceptableReason = isResponseAcceptable(dnsMessage.response);
                    if (unacceptableReason == null) {
                        return dnsMessage;
                    }
                }
            } catch (IOException ioException) {
                ioExceptions.add(ioException);
            }
        }

        // Abort if we the are in "recursive only" mode.
        if (mode == Mode.recursiveOnly) return dnsMessage;

        // Eventually log that we fall back to iterative mode.
        final Level FALLBACK_LOG_LEVEL = Level.FINE;
        if (LOGGER.isLoggable(FALLBACK_LOG_LEVEL) && mode != Mode.iterativeOnly) {
            String logString = "Resolution fall back to iterative mode because: ";
            if (!ioExceptions.isEmpty()) {
                logString += ioExceptions.get(0);
            } else if (dnsMessage == null) {
                logString += " DnsClient did not return a response";
            } else if (unacceptableReason != null) {
                logString += unacceptableReason + ". Response:\n" + dnsMessage;
            } else {
                throw new AssertionError("This should never been reached");
            }
            LOGGER.log(FALLBACK_LOG_LEVEL, logString);
        }

        try {
            dnsMessage = recursiveDnsClient.query(q);
            assert dnsMessage != null;
        } catch (IOException ioException) {
            ioExceptions.add(ioException);
        }

        if (dnsMessage == null) {
            assert !ioExceptions.isEmpty();
            MultipleIoException.throwIfRequired(ioExceptions);
        }

        return dnsMessage;
    }

    @Override
    protected DnsMessage.Builder newQuestion(DnsMessage.Builder questionMessage) {
        return questionMessage;
    }

    @Override
    protected boolean isResponseCacheable(Question q, DnsQueryResult result) {
        return isResponseAcceptable(result.response) == null;
    }

    /**
     * Check if the response from the system's nameserver is acceptable. Must return <code>null</code> if the response
     * is acceptable, or a String describing why it is not acceptable. If the response is not acceptable then
     * {@link ReliableDnsClient} will fall back to resolve the query iteratively.
     *
     * @param response the response we got from the system's nameserver.
     * @return <code>null</code> if the response is acceptable, or a String if not.
     */
    protected String isResponseAcceptable(DnsMessage response) {
        return null;
    }

    @Override
    public void setDataSource(DnsDataSource dataSource) {
        super.setDataSource(dataSource);
        recursiveDnsClient.setDataSource(dataSource);
        dnsClient.setDataSource(dataSource);
    }

    /**
     * Set the mode used when resolving queries.
     *
     * @param mode the mode to use.
     */
    public void setMode(Mode mode) {
        if (mode == null) {
            throw new IllegalArgumentException("Mode must not be null.");
        }
        this.mode = mode;
    }

    public void setUseHardcodedDnsServers(boolean useHardcodedDnsServers) {
        dnsClient.setUseHardcodedDnsServers(useHardcodedDnsServers);
    }

}
