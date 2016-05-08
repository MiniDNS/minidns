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

import de.measite.minidns.dnsserverlookup.AndroidUsingExec;
import de.measite.minidns.dnsserverlookup.AndroidUsingReflection;
import de.measite.minidns.dnsserverlookup.DNSServerLookupMechanism;
import de.measite.minidns.dnsserverlookup.HardcodedDNSServerAddresses;
import de.measite.minidns.dnsserverlookup.UnixUsingEtcResolvConf;
import de.measite.minidns.record.OPT;
import de.measite.minidns.util.MultipleIoException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A minimal DNS client for SRV/A/AAAA/NS and CNAME lookups, with IDN support.
 * This circumvents the missing javax.naming package on android.
 */
public class DNSClient extends AbstractDNSClient {

    static final List<DNSServerLookupMechanism> LOOKUP_MECHANISMS = new ArrayList<>();

    static {
        addDnsServerLookupMechanism(AndroidUsingExec.INSTANCE);
        addDnsServerLookupMechanism(AndroidUsingReflection.INSTANCE);
        addDnsServerLookupMechanism(HardcodedDNSServerAddresses.INSTANCE);
        addDnsServerLookupMechanism(UnixUsingEtcResolvConf.INSTANCE);
    }

    private boolean askForDnssec = false;
    private boolean disableResultFilter = false;

    /**
     * Create a new DNS client using the global default cache.
     */
    public DNSClient() {
        super();
    }

    public DNSClient(DNSCache dnsCache) {
        super(dnsCache);
    }

    @Override
    protected DNSMessage.Builder newQuestion(DNSMessage.Builder message) {
        message.setRecursionDesired(true);
        message.setOptPseudoRecord(dataSource.getUdpPayloadSize(), askForDnssec ? OPT.FLAG_DNSSEC_OK : 0);
        return message;
    }

    @Override
    public DNSMessage query(DNSMessage q) throws IOException {
        // While this query method does in fact re-use query(Question, String)
        // we still do a cache lookup here in order to avoid unnecessary
        // findDNS()calls, which are expensive on Android. Note that we do not
        // put the results back into the Cache, as this is already done by
        // query(Question, String).
        DNSMessage responseMessage = (cache == null) ? null : cache.get(q);
        if (responseMessage != null) {
            return responseMessage;
        }

        final Question question = q.getQuestion();
        String dnsServer[] = findDNS();
        List<IOException> ioExceptions = new ArrayList<>(dnsServer.length);
        for (String dns : dnsServer) {
            try {
                responseMessage = query(q, dns);
                if (responseMessage == null) {
                    continue;
                }
                if (disableResultFilter) {
                    return responseMessage;
                }
                if (responseMessage.responseCode !=
                        DNSMessage.RESPONSE_CODE.NO_ERROR) {
                    LOGGER.warning("Response from " + dns + " asked for " + q.getQuestion() + " with error code: "
                            + responseMessage.responseCode + ".\n" + responseMessage);
                    continue;
                }
                for (Record record : responseMessage.answers) {
                    if (record.isAnswer(question)) {
                        return responseMessage;
                    }
                }
                // TODO Remove the following warning. This is a perfectly valid situation: If there is no RRset of the
                // RR type queried but the name does exists, then the answer section will be empty.
                LOGGER.warning("Response from " + dns + " asked for " + q
                        + " did not contain an answer to the query.\n" + responseMessage);
            } catch (IOException ioe) {
                ioExceptions.add(ioe);
            }
        }
        MultipleIoException.throwIfRequired(ioExceptions);
        return null;
    }

    /**
     * Retrieve a list of currently configured DNS servers.
     *
     * @return The server array.
     */
    public static synchronized String[] findDNS() {
        String[] res = null;
        for (DNSServerLookupMechanism mechanism : LOOKUP_MECHANISMS) {
            res = mechanism.getDnsServerAddresses();
            if (res != null) {
                break;
            }
        }
        return res;
    }

    public static synchronized void addDnsServerLookupMechanism(DNSServerLookupMechanism dnsServerLookup) {
        if (!dnsServerLookup.isAvailable()) {
            LOGGER.fine("Not adding " + dnsServerLookup.getName() + " as it is not available.");
            return;
        }
        LOOKUP_MECHANISMS.add(dnsServerLookup);
        Collections.sort(LOOKUP_MECHANISMS);
    }

    public static synchronized boolean removeDNSServerLookupMechanism(DNSServerLookupMechanism dnsServerLookup) {
        return LOOKUP_MECHANISMS.remove(dnsServerLookup);
    }

    public boolean isAskForDnssec() {
        return askForDnssec;
    }

    public void setAskForDnssec(boolean askForDnssec) {
        this.askForDnssec = askForDnssec;
    }

    public boolean isDisableResultFilter() {
        return disableResultFilter;
    }

    public void setDisableResultFilter(boolean disableResultFilter) {
        this.disableResultFilter = disableResultFilter;
    }
}
