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
import de.measite.minidns.util.MultipleIoException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
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
        addDnsServerLookupMechanism(UnixUsingEtcResolvConf.INSTANCE);
    }

    private final Set<String> nonRaServers = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>(4));

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
        message.getEdnsBuilder().setUdpPayloadSize(dataSource.getUdpPayloadSize()).setDnssecOk(askForDnssec);
        return message;
    }

    @Override
    public DNSMessage query(DNSMessage.Builder queryBuilder) throws IOException {
        DNSMessage q = newQuestion(queryBuilder).build();
        // While this query method does in fact re-use query(Question, String)
        // we still do a cache lookup here in order to avoid unnecessary
        // findDNS()calls, which are expensive on Android. Note that we do not
        // put the results back into the Cache, as this is already done by
        // query(Question, String).
        DNSMessage responseMessage = (cache == null) ? null : cache.get(q);
        if (responseMessage != null) {
            return responseMessage;
        }

        String dnsServer[] = findDNS();
        List<IOException> ioExceptions = new ArrayList<>(dnsServer.length);
        for (String dns : dnsServer) {
            if (nonRaServers.contains(dns)) {
                LOGGER.finer("Skipping " + dns + " because it was marked as \"recursion not available\"");
                continue;
            }

            try {
                responseMessage = query(q, dns);
                if (responseMessage == null) {
                    continue;
                }

                if (!responseMessage.recursionAvailable) {
                    boolean newRaServer = nonRaServers.add(dns);
                    if (newRaServer) {
                        LOGGER.warning("The DNS server "
                                + dns
                                + " returned a response without the \"recursion available\" (RA) flag set. This likely indicates a misconfiguration because the server is not suitable for DNS resolution");
                    }
                    continue;
                }

                if (disableResultFilter) {
                    return responseMessage;
                }

                switch (responseMessage.responseCode) {
                case NO_ERROR:
                case NX_DOMAIN:
                    break;
                default:
                    String warning = "Response from " + dns + " asked for " + q.getQuestion() + " with error code: "
                            + responseMessage.responseCode + '.';
                    if (!LOGGER.isLoggable(Level.FINE)) {
                        // Only append the responseMessage is log level is not fine. If it is fine or higher, the
                        // response has already been logged.
                        warning += "\n" + responseMessage;
                    }
                    LOGGER.warning(warning);
                    // TODO Create new IOException and add to ioExceptions.
                    continue;
                }

                return responseMessage;
            } catch (IOException ioe) {
                ioExceptions.add(ioe);
            }
        }
        MultipleIoException.throwIfRequired(ioExceptions);
        // TODO assert that we never return null here.
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
