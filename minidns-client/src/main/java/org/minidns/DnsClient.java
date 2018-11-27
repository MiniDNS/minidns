/*
 * Copyright 2015-2018 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns;

import org.minidns.MiniDnsException.ErrorResponseException;
import org.minidns.MiniDnsException.NoQueryPossibleException;
import org.minidns.MiniDnsFuture.InternalMiniDnsFuture;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.dnsserverlookup.AndroidUsingExec;
import org.minidns.dnsserverlookup.AndroidUsingReflection;
import org.minidns.dnsserverlookup.DnsServerLookupMechanism;
import org.minidns.dnsserverlookup.IPPortPair;
import org.minidns.dnsserverlookup.UnixUsingEtcResolvConf;
import org.minidns.util.CollectionsUtil;
import org.minidns.util.ExceptionCallback;
import org.minidns.util.InetAddressUtil;
import org.minidns.util.SuccessCallback;
import org.minidns.util.MultipleIoException;

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
public class DnsClient extends AbstractDnsClient {

    static final List<DnsServerLookupMechanism> LOOKUP_MECHANISMS = new CopyOnWriteArrayList<>();

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
    public DnsClient() {
        super();
    }

    public DnsClient(DnsCache dnsCache) {
        super(dnsCache);
    }

    @Override
    protected DnsMessage.Builder newQuestion(DnsMessage.Builder message) {
        message.setRecursionDesired(true);
        message.getEdnsBuilder().setUdpPayloadSize(dataSource.getUdpPayloadSize()).setDnssecOk(askForDnssec);
        return message;
    }

    private List<UpstreamDNSServer> getServerAddresses() {
        List<UpstreamDNSServer> dnsServerAddresses = findDnsAddresses();

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
            dnsServerAddresses.add(new UpstreamDNSServer(selectedHardcodedDnsServerAddress, IPPortPair.DEFAULT_PORT));
        }

        return dnsServerAddresses;
    }

    @Override
    public DnsQueryResult query(DnsMessage.Builder queryBuilder) throws IOException {
        DnsMessage q = newQuestion(queryBuilder).build();
        // While this query method does in fact re-use query(Question, String)
        // we still do a cache lookup here in order to avoid unnecessary
        // findDNS()calls, which are expensive on Android. Note that we do not
        // put the results back into the Cache, as this is already done by
        // query(Question, String).
        DnsQueryResult dnsQueryResult = (cache == null) ? null : cache.get(q);
        if (dnsQueryResult != null) {
            return dnsQueryResult;
        }

        List<UpstreamDNSServer> dnsServerAddresses = getServerAddresses();

        List<IOException> ioExceptions = new ArrayList<>(dnsServerAddresses.size());
        for (UpstreamDNSServer dns : dnsServerAddresses) {
            if (nonRaServers.contains(dns.getServer())) {
                LOGGER.finer("Skipping " + dns + " because it was marked as \"recursion not available\"");
                continue;
            }

            try {
                dnsQueryResult = query(q, dns.getServer(), dns.getPort());
            } catch (IOException ioe) {
                ioExceptions.add(ioe);
                continue;
            }

            DnsMessage responseMessage = dnsQueryResult.response;
            if (!responseMessage.recursionAvailable) {
                boolean newRaServer = nonRaServers.add(dns.getServer());
                if (newRaServer) {
                    LOGGER.warning("The DNS server " + dns
                            + " returned a response without the \"recursion available\" (RA) flag set. This likely indicates a misconfiguration because the server is not suitable for DNS resolution");
                }
                continue;
            }

            if (disableResultFilter) {
                return dnsQueryResult;
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

                ErrorResponseException exception = new ErrorResponseException(q, dnsQueryResult);
                ioExceptions.add(exception);
                continue;
            }

            return dnsQueryResult;
        }
        MultipleIoException.throwIfRequired(ioExceptions);

        // TODO: Shall we add the attempted DNS servers to the exception?
        throw new NoQueryPossibleException(q);
    }

    @Override
    protected MiniDnsFuture<DnsQueryResult, IOException> queryAsync(DnsMessage.Builder queryBuilder) {
        DnsMessage q = newQuestion(queryBuilder).build();
        // While this query method does in fact re-use query(Question, String)
        // we still do a cache lookup here in order to avoid unnecessary
        // findDNS()calls, which are expensive on Android. Note that we do not
        // put the results back into the Cache, as this is already done by
        // query(Question, String).
        DnsQueryResult responseMessage = (cache == null) ? null : cache.get(q);
        if (responseMessage != null) {
            return MiniDnsFuture.from(responseMessage);
        }

        final List<UpstreamDNSServer> dnsServerAddresses = getServerAddresses();

        final InternalMiniDnsFuture<DnsQueryResult, IOException> future = new InternalMiniDnsFuture<>();
        final List<IOException> exceptions = Collections.synchronizedList(new ArrayList<IOException>(dnsServerAddresses.size()));

        // Filter loop.
        Iterator<UpstreamDNSServer> it = dnsServerAddresses.iterator();
        while (it.hasNext()) {
            UpstreamDNSServer dns = it.next();
            if (nonRaServers.contains(dns.getServer())) {
                it.remove();
                LOGGER.finer("Skipping " + dns + " because it was marked as \"recursion not available\"");
                continue;
            }
        }

        List<MiniDnsFuture<DnsQueryResult, IOException>> futures = new ArrayList<>(dnsServerAddresses.size());
        // "Main" loop.
        for (UpstreamDNSServer dns : dnsServerAddresses) {
            if (future.isDone()) {
                for (MiniDnsFuture<DnsQueryResult, IOException> futureToCancel : futures) {
                    futureToCancel.cancel(true);
                }
                break;
            }

            MiniDnsFuture<DnsQueryResult, IOException> f = queryAsync(q, dns.getServer(), dns.getPort());
            f.onSuccess(new SuccessCallback<DnsQueryResult>() {
                @Override
                public void onSuccess(DnsQueryResult result) {
                    future.setResult(result);
                }
            });
            f.onError(new ExceptionCallback<IOException>() {
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
     * The addresses are discovered by using one (or more) of the configured {@link DnsServerLookupMechanism}s.
     * </p>
     *
     * @return A list of DNS server IP addresses configured for this system.
     */
    public static List<IPPortPair> findDNS() {
        List<IPPortPair> res = null;
        for (DnsServerLookupMechanism mechanism : LOOKUP_MECHANISMS) {
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
            Iterator<IPPortPair> it = res.iterator();
            while (it.hasNext()) {
                IPPortPair potentialDnsServer = it.next();
                if (!InetAddressUtil.isIpAddress(potentialDnsServer.getIp())) {
                    LOGGER.warning("The DNS server lookup mechanism '" + mechanism.getName()
                            + "' returned an invalid non-IP address result: '" + potentialDnsServer + "'");
                    it.remove();
                } else if (blacklistedDnsServers.contains(potentialDnsServer.getIp())) {
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
    public static List<UpstreamDNSServer> findDnsAddresses() {
        // The findDNS() method contract guarantees that only IP addresses will be returned.
        List<IPPortPair> res = findDNS();

        if (res == null) {
            return new ArrayList<>();
        }

        final IpVersionSetting setting = DEFAULT_IP_VERSION_SETTING;

        List<UpstreamDNSServer> ipv4DnsServer = null;
        List<UpstreamDNSServer> ipv6DnsServer = null;
        if (setting.v4) {
            ipv4DnsServer = new ArrayList<>(res.size());
        }
        if (setting.v6) {
            ipv6DnsServer = new ArrayList<>(res.size());
        }

        for (IPPortPair dnsServer : res) {
            // The following invariant must hold: "dnsServerString is a IP address". Therefore findDNS() must only return a List of Strings
            // representing IP addresses. Otherwise the following call of getByName(String) may perform a DNS lookup without MiniDNS being
            // involved. Something we want to avoid.
            assert (InetAddressUtil.isIpAddress(dnsServer.getIp()));
            assert (dnsServer.getPort() >= 1 && dnsServer.getPort() <= 65535);

            InetAddress dnsServerAddress;
            try {
                dnsServerAddress = InetAddress.getByName(dnsServer.getIp());
            } catch (UnknownHostException e) {
                LOGGER.log(Level.SEVERE, "Could not transform '" + dnsServer + "' to InetAddress", e);
                continue;
            }
            if (dnsServerAddress instanceof Inet4Address) {
                if (!setting.v4) {
                    continue;
                }
                Inet4Address ipv4DnsServerAddress = (Inet4Address) dnsServerAddress;
                ipv4DnsServer.add(new UpstreamDNSServer(ipv4DnsServerAddress, dnsServer.getPort()));
            } else if (dnsServerAddress instanceof Inet6Address) {
                if (!setting.v6) {
                    continue;
                }
                Inet6Address ipv6DnsServerAddress = (Inet6Address) dnsServerAddress;
                ipv6DnsServer.add(new UpstreamDNSServer(ipv6DnsServerAddress, dnsServer.getPort()));
            } else {
                throw new AssertionError("The address '" + dnsServerAddress + "' is neither of type Inet(4|6)Address");
            }
        }

        List<UpstreamDNSServer> dnsServers = new LinkedList<>();

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

    public static void addDnsServerLookupMechanism(DnsServerLookupMechanism dnsServerLookup) {
        if (!dnsServerLookup.isAvailable()) {
            LOGGER.fine("Not adding " + dnsServerLookup.getName() + " as it is not available.");
            return;
        }
        synchronized (LOOKUP_MECHANISMS) {
            // We can't use Collections.sort(CopyOnWriteArrayList) with Java 7. So we first create a temp array, sort it, and replace
            // LOOKUP_MECHANISMS with the result. For more information about the Java 7 Collections.sort(CopyOnWriteArarayList) issue see
            // http://stackoverflow.com/a/34827492/194894
            // TODO: Remove that workaround once MiniDNS is Java 8 only.
            ArrayList<DnsServerLookupMechanism> tempList = new ArrayList<>(LOOKUP_MECHANISMS.size() + 1);
            tempList.addAll(LOOKUP_MECHANISMS);
            tempList.add(dnsServerLookup);

            // Sadly, this Collections.sort() does not with the CopyOnWriteArrayList on Java 7.
            Collections.sort(tempList);

            LOOKUP_MECHANISMS.clear();
            LOOKUP_MECHANISMS.addAll(tempList);
        }
    }

    public static boolean removeDNSServerLookupMechanism(DnsServerLookupMechanism dnsServerLookup) {
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

    public static class UpstreamDNSServer {
        private InetAddress server;
        private int port;

        public UpstreamDNSServer(InetAddress server, int port) {
            this.server = server;
            this.port = port;
        }

        public InetAddress getServer() {
            return server;
        }

        public int getPort() {
            return port;
        }
    }
}
