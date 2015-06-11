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
package de.measite.minidns;

import de.measite.minidns.dnsserverlookup.AndroidUsingExec;
import de.measite.minidns.dnsserverlookup.AndroidUsingReflection;
import de.measite.minidns.dnsserverlookup.DNSServerLookupMechanism;
import de.measite.minidns.dnsserverlookup.HardcodedDNSServerAddresses;
import de.measite.minidns.record.OPT;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

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
    }

    private boolean askForDnssec = false;
    private boolean disableResultFilter = false;

    public DNSClient(DNSCache dnsCache) {
        super(dnsCache);
    }

    public DNSClient(final Map<Question, DNSMessage> cache) {
        super(cache);
    }

    @Override
    protected DNSMessage buildMessage(Question question) {
        DNSMessage message = new DNSMessage();
        message.setQuestions(question);
        message.setRecursionDesired(true);
        message.setId(random.nextInt());
        message.setOptPseudoRecord(dataSource.getUdpPayloadSize(), askForDnssec ? OPT.FLAG_DNSSEC_OK : 0);
        return message;
    }

    /**
     * Query the system DNS server for one entry.
     *
     * @param q The question section of the DNS query.
     * @return The response (or null on timeout/error).
     */
    public DNSMessage query(Question q) {
        // While this query method does in fact re-use query(Question, String)
        // we still do a cache lookup here in order to avoid unnecessary
        // findDNS()calls, which are expensive on Android. Note that we do not
        // put the results back into the Cache, as this is already done by
        // query(Question, String).
        DNSMessage message = (cache == null) ? null : cache.get(q);
        if (message != null) {
            return message;
        }

        String dnsServer[] = findDNS();
        for (String dns : dnsServer) {
            try {
                message = query(q, dns);
                if (message == null) {
                    continue;
                }
                if (disableResultFilter) {
                    return message;
                }
                if (message.getResponseCode() !=
                        DNSMessage.RESPONSE_CODE.NO_ERROR) {
                    continue;
                }
                for (Record record : message.getAnswers()) {
                    if (record.isAnswer(q)) {
                        return message;
                    }
                }
            } catch (IOException ioe) {
                LOGGER.log(Level.FINE, "IOException in query", ioe);
            }
        }
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
