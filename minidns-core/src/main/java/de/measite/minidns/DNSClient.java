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
import de.measite.minidns.dnsserverlookup.UnixUsingEtcResolvConf;
import de.measite.minidns.util.CollectionsUtil;
import de.measite.minidns.util.InetAddressUtil;
import de.measite.minidns.util.MultipleIoException;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.logging.Level;

/**
 * A minimal DNS client for SRV/A/AAAA/NS and CNAME lookups, with IDN support.
 * This circumvents the missing javax.naming package on android.
 */
public class DNSClient extends AbstractDNSClient {

    static final List<DNSServerLookupMechanism> LOOKUP_MECHANISMS = new ArrayList<>();

    static final Set<Inet4Address> STATIC_IPV4_DNS_SERVERS = new CopyOnWriteArraySet<>();
    static final Set<Inet6Address> STATIC_IPV6_DNS_SERVERS = new CopyOnWriteArraySet<>();

    static {
        addDnsServerLookupMechanism(AndroidUsingExec.INSTANCE);
        addDnsServerLookupMechanism(AndroidUsingReflection.INSTANCE);
        addDnsServerLookupMechanism(UnixUsingEtcResolvConf.INSTANCE);

        try {
            Inet4Address googleV4Dns = InetAddressUtil.ipv4From("8.8.8.8");
            STATIC_IPV4_DNS_SERVERS.add(googleV4Dns);
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.WARNING, "Could not add static IPv4 DNS Server", e);
        }

        try {
            Inet6Address googleV6Dns = InetAddressUtil.ipv6From("[2001:4860:4860::8888]");
            STATIC_IPV6_DNS_SERVERS.add(googleV6Dns);
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.WARNING, "Could not add static IPv6 DNS Server", e);
        }
    }

    private static final Set<String> blacklistedDnsServers = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>(4));

    private final Set<InetAddress> nonRaServers = Collections.newSetFromMap(new ConcurrentHashMap<InetAddress, Boolean>(4));

    private boolean askForDnssec = false;
    private boolean disableResultFilter = false;

    private boolean useHardcodedDnsServers = true;

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

        String dnsServerStrings[] = findDNS();

        int dnsServerCount;
        if (dnsServerStrings == null) {
            dnsServerCount = 0;
        } else {
            dnsServerCount = dnsServerStrings.length;
        }

        List<InetAddress> dnsServerAddresses = new ArrayList<>(dnsServerCount + 2);
        for (String dnsServerString : dnsServerStrings) {
            if (dnsServerString == null || dnsServerString.isEmpty()) {
                LOGGER.finest("findDns() returned null or empty string as dns server");
                continue;
            }
            InetAddress dnsServerAddress = InetAddress.getByName(dnsServerString);
            dnsServerAddresses.add(dnsServerAddress);
        }

        InetAddress[] selectedHardcodedDnsServerAddresses = new InetAddress[2];
        if (useHardcodedDnsServers) {
            InetAddress primaryHardcodedDnsServer = null, secondaryHardcodedDnsServer = null;
            switch (ipVersionSetting) {
            case v4v6:
                primaryHardcodedDnsServer = getRandomHardcodedIpv4DnsServer();
                secondaryHardcodedDnsServer = getRandomHarcodedIpv6DnsServer();
                break;
            case v6v4:
                primaryHardcodedDnsServer = getRandomHarcodedIpv6DnsServer();
                secondaryHardcodedDnsServer = getRandomHardcodedIpv4DnsServer();
                break;
            case v4only:
                primaryHardcodedDnsServer = getRandomHardcodedIpv4DnsServer();
                break;
            case v6only:
                primaryHardcodedDnsServer = getRandomHarcodedIpv6DnsServer();
                break;
            }
            selectedHardcodedDnsServerAddresses[0] = primaryHardcodedDnsServer;
            selectedHardcodedDnsServerAddresses[1] = secondaryHardcodedDnsServer;
        }
        for (InetAddress selectedHardcodedDnsServerAddress : selectedHardcodedDnsServerAddresses) {
            if (selectedHardcodedDnsServerAddress == null) continue;
            dnsServerAddresses.add(selectedHardcodedDnsServerAddress);
        }

        List<IOException> ioExceptions = new ArrayList<>(dnsServerAddresses.size());
        for (InetAddress dns : dnsServerAddresses) {
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
        String[] resArray = null;
        for (DNSServerLookupMechanism mechanism : LOOKUP_MECHANISMS) {
            resArray = mechanism.getDnsServerAddresses();
            if (resArray == null) {
                continue;
            }

            List<String> res = new ArrayList<>(Arrays.asList(resArray));

            Iterator<String> it = res.iterator();
            while (it.hasNext()) {
                String potentialDnsServer = it.next();

                if (blacklistedDnsServers.contains(potentialDnsServer)) {
                    LOGGER.fine("The DNS server lookup mechanism '" + mechanism.getName()
                    + "' returned a blacklisted result: '" + potentialDnsServer + "'");
                    it.remove();
                }
            }

            if (!res.isEmpty()) {
                break;
            }
        }

        return resArray;
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

    public static boolean addBlacklistedDnsServer(String dnsServer) {
        return blacklistedDnsServers.add(dnsServer);
    }

    public static boolean removeBlacklistedDnsServer(String dnsServer) {
        return blacklistedDnsServers.remove(dnsServer);
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

    public boolean isUseHardcodedDnsServersEnabled() {
        return useHardcodedDnsServers;
    }

    public void setUseHardcodedDnsServers(boolean useHardcodedDnsServers) {
        this.useHardcodedDnsServers = useHardcodedDnsServers;
    }

    public InetAddress getRandomHardcodedIpv4DnsServer() {
        return CollectionsUtil.getRandomFrom(STATIC_IPV4_DNS_SERVERS, insecureRandom);
    }

    public InetAddress getRandomHarcodedIpv6DnsServer() {
        return CollectionsUtil.getRandomFrom(STATIC_IPV6_DNS_SERVERS, insecureRandom);
    }
}
