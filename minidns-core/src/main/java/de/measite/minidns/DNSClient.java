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
package de.measite.minidns;

import de.measite.minidns.MiniDnsFuture.ExceptionCallback;
import de.measite.minidns.MiniDnsFuture.InternalMiniDnsFuture;
import de.measite.minidns.MiniDnsFuture.SuccessCallback;
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
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.logging.Level;

/**
 * A minimal DNS client for SRV/A/AAAA/NS and CNAME lookups, with IDN support.
 * This circumvents the missing javax.naming package on android.
 */
public class DNSClient extends AbstractDNSClient {

    static final List<DNSServerLookupMechanism> LOOKUP_MECHANISMS = new CopyOnWriteArrayList<>();

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

    private List<InetAddress> getServerAddresses() {
        List<InetAddress> dnsServerAddresses = findDnsAddresses();

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

        return dnsServerAddresses;
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

        List<InetAddress> dnsServerAddresses = getServerAddresses();

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

    @Override
    protected MiniDnsFuture<DNSMessage, IOException> queryAsync(DNSMessage.Builder queryBuilder) {
        DNSMessage q = newQuestion(queryBuilder).build();
        // While this query method does in fact re-use query(Question, String)
        // we still do a cache lookup here in order to avoid unnecessary
        // findDNS()calls, which are expensive on Android. Note that we do not
        // put the results back into the Cache, as this is already done by
        // query(Question, String).
        DNSMessage responseMessage = (cache == null) ? null : cache.get(q);
        if (responseMessage != null) {
            return MiniDnsFuture.from(responseMessage);
        }

        final List<InetAddress> dnsServerAddresses = getServerAddresses();

        final InternalMiniDnsFuture<DNSMessage, IOException> future = new InternalMiniDnsFuture<>();
        final List<IOException> exceptions = Collections.synchronizedList(new ArrayList<IOException>(dnsServerAddresses.size()));

        // Filter loop.
        Iterator<InetAddress> it = dnsServerAddresses.iterator();
        while (it.hasNext()) {
            InetAddress dns = it.next();
            if (nonRaServers.contains(dns)) {
                it.remove();
                LOGGER.finer("Skipping " + dns + " because it was marked as \"recursion not available\"");
                continue;
            }
        }

        List<MiniDnsFuture<DNSMessage, IOException>> futures = new ArrayList<>(dnsServerAddresses.size());
        // "Main" loop.
        for (InetAddress dns : dnsServerAddresses) {
            if (future.isDone()) {
                for (MiniDnsFuture<DNSMessage, IOException> futureToCancel : futures) {
                    futureToCancel.cancel(true);
                }
                break;
            }

            MiniDnsFuture<DNSMessage, IOException> f = queryAsync(q, dns);
            f.onSuccessOrError(new SuccessCallback<DNSMessage>() {
                @Override
                public void onSuccess(DNSMessage result) {
                    future.setResult(result);
                }
            }, new ExceptionCallback<IOException>() {
                @Override
                public void processException(IOException exception) {
                    exceptions.add(exception);
                    if (exceptions.size() == dnsServerAddresses.size()) {
                        future.setException(MultipleIoException.toIOException(exceptions));
                    }
                }
            });
            futures.add(f);
        }

        return future;
    }

    /**
     * Retrieve a list of currently configured DNS servers IP addresses. This method does verify that only IP addresses are returned and
     * nothing else (e.g. DNS names).
     * <p>
     * The addresses are discovered by using one (or more) of the configured {@link DNSServerLookupMechanism}s.
     * </p>
     *
     * @return A list of DNS server IP addresses configured for this system.
     */
    public static List<String> findDNS() {
        List<String> res = null;
        for (DNSServerLookupMechanism mechanism : LOOKUP_MECHANISMS) {
            res = mechanism.getDnsServerAddresses();
            if (res == null) {
                continue;
            }

            assert(!res.isEmpty());

            // We could cache if res only contains IP addresses and avoid the verification in case. Not sure if its really that beneficial
            // though, because the list returned by the server mechanism is rather short.

            // Verify the returned DNS servers: Ensure that only valid IP addresses are returned. We want to avoid that something else,
            // especially a valid DNS name is returned, as this would cause the following String to InetAddress conversation using
            // getByName(String) to cause a DNS lookup, which would be performed outside of the realm of MiniDNS and therefore also outside
            // of its DNSSEC guarantees.
            Iterator<String> it = res.iterator();
            while (it.hasNext()) {
                String potentialDnsServer = it.next();
                if (!InetAddressUtil.isIpAddress(potentialDnsServer)) {
                    LOGGER.warning("The DNS server lookup mechanism '" + mechanism.getName()
                            + "' returned an invalid non-IP address result: '" + potentialDnsServer + "'");
                    it.remove();
                } else if (blacklistedDnsServers.contains(potentialDnsServer)) {
                    LOGGER.fine("The DNS server lookup mechanism '" + mechanism.getName()
                    + "' returned a blacklisted result: '" + potentialDnsServer + "'");
                    it.remove();
                }
            }

            if (!res.isEmpty()) {
                break;
            } else {
                LOGGER.warning("The DNS server lookup mechanism '" + mechanism.getName()
                        + "' returned not a single valid IP address after sanitazion");
            }
        }

        return res;
    }

    /**
     * Retrieve a list of currently configured DNS server addresses.
     * <p>
     * Note that unlike {@link #findDNS()}, the list returned by this method
     * will take the IP version setting into account, and order the list by the
     * preferred address types (IPv4/v6). The returned list is modifiable.
     * </p>
     *
     * @return A list of DNS server addresses.
     * @see #findDNS()
     */
    public static List<InetAddress> findDnsAddresses() {
        // The findDNS() method contract guarantees that only IP addresses will be returned.
        List<String> res = findDNS();

        if (res == null) {
            return new ArrayList<>();
        }

        final IpVersionSetting setting = DEFAULT_IP_VERSION_SETTING;

        List<Inet4Address> ipv4DnsServer = null;
        List<Inet6Address> ipv6DnsServer = null;
        if (setting.v4) {
            ipv4DnsServer = new ArrayList<>(res.size());
        }
        if (setting.v6) {
            ipv6DnsServer = new ArrayList<>(res.size());
        }

        for (String dnsServerString : res) {
            // The following invariant must hold: "dnsServerString is a IP address". Therefore findDNS() must only return a List of Strings
            // representing IP addresses. Otherwise the following call of getByName(String) may perform a DNS lookup without MiniDNS being
            // involved. Something we want to avoid.
            assert (InetAddressUtil.isIpAddress(dnsServerString));

            InetAddress dnsServerAddress;
            try {
                dnsServerAddress = InetAddress.getByName(dnsServerString);
            } catch (UnknownHostException e) {
                LOGGER.log(Level.SEVERE, "Could not transform '" + dnsServerString + "' to InetAddress", e);
                continue;
            }
            if (dnsServerAddress instanceof Inet4Address) {
                if (!setting.v4) {
                    continue;
                }
                Inet4Address ipv4DnsServerAddress = (Inet4Address) dnsServerAddress;
                ipv4DnsServer.add(ipv4DnsServerAddress);
            } else if (dnsServerAddress instanceof Inet6Address) {
                if (!setting.v6) {
                    continue;
                }
                Inet6Address ipv6DnsServerAddress = (Inet6Address) dnsServerAddress;
                ipv6DnsServer.add(ipv6DnsServerAddress);
            } else {
                throw new AssertionError("The address '" + dnsServerAddress + "' is neither of type Inet(4|6)Address");
            }
        }

        List<InetAddress> dnsServers = new LinkedList<>();

        switch (setting) {
        case v4v6:
            dnsServers.addAll(ipv4DnsServer);
            dnsServers.addAll(ipv6DnsServer);
            break;
        case v6v4:
            dnsServers.addAll(ipv6DnsServer);
            dnsServers.addAll(ipv4DnsServer);
            break;
        case v4only:
            dnsServers.addAll(ipv4DnsServer);
            break;
        case v6only:
            dnsServers.addAll(ipv6DnsServer);
            break;
        }
        return dnsServers;
    }

    public static void addDnsServerLookupMechanism(DNSServerLookupMechanism dnsServerLookup) {
        if (!dnsServerLookup.isAvailable()) {
            LOGGER.fine("Not adding " + dnsServerLookup.getName() + " as it is not available.");
            return;
        }
        synchronized (LOOKUP_MECHANISMS) {
            // We can't use Collections.sort(CopyOnWriteArrayList) with Java 7. So we first create a temp array, sort it, and replace
            // LOOKUP_MECHANISMS with the result. For more information about the Java 7 Collections.sort(CopyOnWriteArarayList) issue see
            // http://stackoverflow.com/a/34827492/194894
            // TODO: Remove that workaround once MiniDNS is Java 8 only.
            ArrayList<DNSServerLookupMechanism> tempList = new ArrayList<>(LOOKUP_MECHANISMS.size() + 1);
            tempList.addAll(LOOKUP_MECHANISMS);
            tempList.add(dnsServerLookup);

            // Sadly, this Collections.sort() does not with the CopyOnWriteArrayList on Java 7.
            Collections.sort(tempList);

            LOOKUP_MECHANISMS.clear();
            LOOKUP_MECHANISMS.addAll(tempList);
        }
    }

    public static boolean removeDNSServerLookupMechanism(DNSServerLookupMechanism dnsServerLookup) {
        synchronized (LOOKUP_MECHANISMS) {
            return LOOKUP_MECHANISMS.remove(dnsServerLookup);
        }
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
