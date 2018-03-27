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
package org.minidns.iterative;

import org.minidns.AbstractDNSClient;
import org.minidns.DNSCache;
import org.minidns.DNSMessage;
import org.minidns.DNSName;
import org.minidns.Question;
import org.minidns.Record;
import org.minidns.Record.TYPE;
import org.minidns.iterative.IterativeClientException.LoopDetected;
import org.minidns.record.A;
import org.minidns.record.AAAA;
import org.minidns.record.RRWithTarget;
import org.minidns.record.Data;
import org.minidns.record.InternetAddressRR;
import org.minidns.record.NS;
import org.minidns.util.MultipleIoException;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;

public class IterativeDNSClient extends AbstractDNSClient {

    private static final Map<Character, InetAddress> IPV4_ROOT_SERVER_MAP = new HashMap<>();

    private static final Map<Character, InetAddress> IPV6_ROOT_SERVER_MAP = new HashMap<>();

    protected static final Inet4Address[] IPV4_ROOT_SERVERS = new Inet4Address[] {
        rootServerInet4Address('a', 198,  41,   0,   4),
        rootServerInet4Address('b', 192, 228,  79, 201),
        rootServerInet4Address('c', 192,  33,   4,  12),
        rootServerInet4Address('d', 199,   7,  91 , 13),
        rootServerInet4Address('e', 192, 203, 230,  10),
        rootServerInet4Address('f', 192,   5,   5, 241),
        rootServerInet4Address('g', 192, 112,  36,   4),
        rootServerInet4Address('h', 198,  97, 190,  53),
        rootServerInet4Address('i', 192,  36, 148,  17),
        rootServerInet4Address('j', 192,  58, 128,  30),
        rootServerInet4Address('k', 193,   0,  14, 129),
        rootServerInet4Address('l', 199,   7,  83,  42),
        rootServerInet4Address('m', 202,  12,  27,  33),
    };

    protected static final Inet6Address[] IPV6_ROOT_SERVERS = new Inet6Address[] {
        rootServerInet6Address('a', 0x2001, 0x0503, 0xba3e, 0x0000, 0x0000, 0x000, 0x0002, 0x0030),
        rootServerInet6Address('b', 0x2001, 0x0500, 0x0084, 0x0000, 0x0000, 0x000, 0x0000, 0x000b),
        rootServerInet6Address('c', 0x2001, 0x0500, 0x0002, 0x0000, 0x0000, 0x000, 0x0000, 0x000c),
        rootServerInet6Address('d', 0x2001, 0x0500, 0x002d, 0x0000, 0x0000, 0x000, 0x0000, 0x000d),
        rootServerInet6Address('f', 0x2001, 0x0500, 0x002f, 0x0000, 0x0000, 0x000, 0x0000, 0x000f),
        rootServerInet6Address('h', 0x2001, 0x0500, 0x0001, 0x0000, 0x0000, 0x000, 0x0000, 0x0053),
        rootServerInet6Address('i', 0x2001, 0x07fe, 0x0000, 0x0000, 0x0000, 0x000, 0x0000, 0x0053),
        rootServerInet6Address('j', 0x2001, 0x0503, 0x0c27, 0x0000, 0x0000, 0x000, 0x0002, 0x0030),
        rootServerInet6Address('l', 0x2001, 0x0500, 0x0003, 0x0000, 0x0000, 0x000, 0x0000, 0x0042),
        rootServerInet6Address('m', 0x2001, 0x0dc3, 0x0000, 0x0000, 0x0000, 0x000, 0x0000, 0x0035),
    };

    int maxSteps = 128;

    /**
     * Create a new recursive DNS client using the global default cache.
     */
    public IterativeDNSClient() {
        super();
    }

    /**
     * Create a new recursive DNS client with the given DNS cache.
     *
     * @param cache The backend DNS cache.
     */
    public IterativeDNSClient(DNSCache cache) {
        super(cache);
    }

    /**
     * Recursively query the DNS system for one entry.
     *
     * @param queryBuilder The query DNS message builder.
     * @return The response (or null on timeout/error).
     * @throws IOException if an IO error occurs.
     */
    @Override
    protected DNSMessage query(DNSMessage.Builder queryBuilder) throws IOException {
        DNSMessage q = queryBuilder.build();
        ResolutionState resolutionState = new ResolutionState(this);
        DNSMessage message = queryRecursive(resolutionState, q);
        return message;
    }

    private Inet4Address getRandomIpv4RootServer() {
        return IPV4_ROOT_SERVERS[insecureRandom.nextInt(IPV4_ROOT_SERVERS.length)];
    }

    private Inet6Address getRandomIpv6RootServer() {
        return IPV6_ROOT_SERVERS[insecureRandom.nextInt(IPV6_ROOT_SERVERS.length)];
    }

    private static InetAddress[] getTargets(Collection<? extends InternetAddressRR> primaryTargets,
            Collection<? extends InternetAddressRR> secondaryTargets) {
        InetAddress[] res = new InetAddress[2];

        for (InternetAddressRR arr : primaryTargets) {
            if (res[0] == null) {
                res[0] = arr.getInetAddress();
                // If secondaryTargets is empty, then try to get the second target out of the set of primaryTargets.
                if (secondaryTargets.isEmpty()) {
                    continue;
                }
            }
            if (res[1] == null) {
                res[1] = arr.getInetAddress();
            }
            break;
        }

        for (InternetAddressRR arr : secondaryTargets) {
            if (res[0] == null) {
                res[0] = arr.getInetAddress();
                continue;
            }
            if (res[1] == null) {
                res[1] = arr.getInetAddress();
            }
            break;
        }

        return res;
    }

    private DNSMessage queryRecursive(ResolutionState resolutionState, DNSMessage q) throws IOException {
        InetAddress primaryTarget = null, secondaryTarget = null;

        Question question = q.getQuestion();
        DNSName parent = question.name.getParent();

        switch (ipVersionSetting) {
        case v4only:
            for (A a : getCachedIPv4NameserverAddressesFor(parent)) {
                if (primaryTarget == null) {
                    primaryTarget = a.getInetAddress();
                    continue;
                }
                secondaryTarget = a.getInetAddress();
                break;
            }
            break;
        case v6only:
            for (AAAA aaaa : getCachedIPv6NameserverAddressesFor(parent)) {
                if (primaryTarget == null) {
                    primaryTarget = aaaa.getInetAddress();
                    continue;
                }
                secondaryTarget = aaaa.getInetAddress();
                break;
            }
            break;
        case v4v6:
            InetAddress[] v4v6targets = getTargets(getCachedIPv4NameserverAddressesFor(parent), getCachedIPv6NameserverAddressesFor(parent));
            primaryTarget = v4v6targets[0];
            secondaryTarget = v4v6targets[1];
            break;
        case v6v4:
            InetAddress[] v6v4targets = getTargets(getCachedIPv6NameserverAddressesFor(parent), getCachedIPv4NameserverAddressesFor(parent));
            primaryTarget = v6v4targets[0];
            secondaryTarget = v6v4targets[1];
            break;
        default:
            throw new AssertionError();
        }

        DNSName authoritativeZone = parent;
        if (primaryTarget == null) {
            authoritativeZone = DNSName.ROOT;
            switch (ipVersionSetting) {
            case v4only:
                primaryTarget = getRandomIpv4RootServer();
                break;
            case v6only:
                primaryTarget = getRandomIpv6RootServer();
                break;
            case v4v6:
                primaryTarget = getRandomIpv4RootServer();
                secondaryTarget = getRandomIpv6RootServer();
                break;
            case v6v4:
                primaryTarget = getRandomIpv6RootServer();
                secondaryTarget = getRandomIpv4RootServer();
                break;
            }
        }

        List<IOException> ioExceptions = new LinkedList<>();

        try {
            return queryRecursive(resolutionState, q, primaryTarget, authoritativeZone);
        } catch (IOException ioException) {
            abortIfFatal(ioException);
            ioExceptions.add(ioException);
        }

        if (secondaryTarget != null) {
            try {
                return queryRecursive(resolutionState, q, secondaryTarget, authoritativeZone);
            } catch (IOException ioException) {
                ioExceptions.add(ioException);
            }
        }

        MultipleIoException.throwIfRequired(ioExceptions);
        return null;
    }

    private DNSMessage queryRecursive(ResolutionState resolutionState, DNSMessage q, InetAddress address, DNSName authoritativeZone) throws IOException {
        resolutionState.recurse(address, q);

        DNSMessage resMessage = query(q, address);

        if (resMessage == null) {
            // TODO throw exception here?
            return null;
        }

        if (resMessage.authoritativeAnswer) {
            return resMessage;
        }

        if (cache != null) {
            cache.offer(q, resMessage, authoritativeZone);
        }

        List<Record<? extends Data>> authorities = resMessage.copyAuthority();

        List<IOException> ioExceptions = new LinkedList<>();

        // Glued NS first
        for (Iterator<Record<? extends Data>> iterator = authorities.iterator(); iterator.hasNext(); ) {
            Record<? extends Data> record = iterator.next();
            if (record.type != TYPE.NS) {
                iterator.remove();
                continue;
            }
            DNSName name = ((NS) record.payloadData).target;
            IpResultSet gluedNs = searchAdditional(resMessage, name);
            for (Iterator<InetAddress> addressIterator = gluedNs.addresses.iterator(); addressIterator.hasNext(); ) {
                InetAddress target = addressIterator.next();
                DNSMessage recursive = null;
                try {
                    recursive = queryRecursive(resolutionState, q, target, record.name);
                } catch (IOException e) {
                   abortIfFatal(e);
                   LOGGER.log(Level.FINER, "Exception while recursing", e);
                   resolutionState.decrementSteps();
                   ioExceptions.add(e);
                   if (!addressIterator.hasNext()) {
                       iterator.remove();
                   }
                   continue;
                }
                return recursive;
            }
        }

        // Try non-glued NS
        for (Record<? extends Data> record : authorities) {
            final Question question = q.getQuestion();
            DNSName name = ((NS) record.payloadData).target;

            // Loop prevention: If this non-glued NS equals the name we question for and if the question is about a A or
            // AAAA RR, then we should not continue here as it would result in an endless loop.
            if (question.name.equals(name) && (question.type == TYPE.A || question.type == TYPE.AAAA))
                continue;

            IpResultSet res = null;
            try {
                res = resolveIpRecursive(resolutionState, name);
            } catch (IOException e) {
                resolutionState.decrementSteps();
                ioExceptions.add(e);
            }
            if (res == null) {
                continue;
            }

            for (InetAddress target : res.addresses) {
                DNSMessage recursive = null;
                try {
                    recursive = queryRecursive(resolutionState, q, target, record.name);
                } catch (IOException e) {
                    resolutionState.decrementSteps();
                    ioExceptions.add(e);
                    continue;
                }
                return recursive;
            }
        }

        MultipleIoException.throwIfRequired(ioExceptions);

        // TODO throw exception here? Reaching this point would mean we did not receive an authoritative answer, nor
        // where we able to find glue records or the IPs of the next nameservers.
        return null;
    }

    private IpResultSet resolveIpRecursive(ResolutionState resolutionState, DNSName name) throws IOException {
        IpResultSet.Builder res = newIpResultSetBuilder();

        if (ipVersionSetting.v4) {
            // TODO Try to retrieve A records for name out from cache.
            Question question = new Question(name, TYPE.A);
            final DNSMessage query = getQueryFor(question);
            DNSMessage aMessage = queryRecursive(resolutionState, query);
            if (aMessage != null) {
                for (Record<? extends Data> answer : aMessage.answerSection) {
                    if (answer.isAnswer(question)) {
                        InetAddress inetAddress = inetAddressFromRecord(name.ace, (A) answer.payloadData);
                        res.ipv4Addresses.add(inetAddress);
                    } else if (answer.type == TYPE.CNAME && answer.name.equals(name)) {
                        return resolveIpRecursive(resolutionState, ((RRWithTarget) answer.payloadData).target);
                    }
                }
            }
        }

        if (ipVersionSetting.v6) {
            // TODO Try to retrieve AAAA records for name out from cache.
            Question question = new Question(name, TYPE.AAAA);
            final DNSMessage query = getQueryFor(question);
            DNSMessage aMessage = queryRecursive(resolutionState, query);
            if (aMessage != null) {
                for (Record<? extends Data> answer : aMessage.answerSection) {
                    if (answer.isAnswer(question)) {
                        InetAddress inetAddress = inetAddressFromRecord(name.ace, (AAAA) answer.payloadData);
                        res.ipv6Addresses.add(inetAddress);
                    } else if (answer.type == TYPE.CNAME && answer.name.equals(name)) {
                        return resolveIpRecursive(resolutionState, ((RRWithTarget) answer.payloadData).target);
                    }
                }
            }
        }

        return res.build();
    }

    @SuppressWarnings("incomplete-switch")
    private IpResultSet searchAdditional(DNSMessage message, DNSName name) {
        IpResultSet.Builder res = newIpResultSetBuilder();
        for (Record<? extends Data> record : message.additionalSection) {
            if (!record.name.equals(name)) {
                continue;
            }
            switch (record.type) {
            case A:
                res.ipv4Addresses.add(inetAddressFromRecord(name.ace, ((A) record.payloadData)));
                break;
            case AAAA:
                res.ipv6Addresses.add(inetAddressFromRecord(name.ace, ((AAAA) record.payloadData)));
                break;
            }
        }
        return res.build();
    }

    private static InetAddress inetAddressFromRecord(String name, A recordPayload) {
        try {
            return InetAddress.getByAddress(name, recordPayload.getIp());
        } catch (UnknownHostException e) {
            // This will never happen
            throw new RuntimeException(e);
        }
    }

    private static InetAddress inetAddressFromRecord(String name, AAAA recordPayload) {
        try {
            return InetAddress.getByAddress(name, recordPayload.getIp());
        } catch (UnknownHostException e) {
            // This will never happen
            throw new RuntimeException(e);
        }
    }

    public static List<InetAddress> getRootServer(char rootServerId) {
        return getRootServer(rootServerId, DEFAULT_IP_VERSION_SETTING);
    }

    public static List<InetAddress> getRootServer(char rootServerId, IpVersionSetting setting) {
        InetAddress ipv4Root = IPV4_ROOT_SERVER_MAP.get(rootServerId);
        InetAddress ipv6Root = IPV6_ROOT_SERVER_MAP.get(rootServerId);
        List<InetAddress> res = new ArrayList<>(2);
        switch (setting) {
        case v4only:
            if (ipv4Root != null) {
                res.add(ipv4Root);
            }
            break;
        case v6only:
            if (ipv6Root != null) {
                res.add(ipv6Root);
            }
            break;
        case v4v6:
            if (ipv4Root != null) {
                res.add(ipv4Root);
            }
            if (ipv6Root != null) {
                res.add(ipv6Root);
            }
            break;
        case v6v4:
            if (ipv6Root != null) {
                res.add(ipv6Root);
            }
            if (ipv4Root != null) {
                res.add(ipv4Root);
            }
            break;
        }
        return res;
    }

    private static Inet4Address rootServerInet4Address(char rootServerId, int addr0, int addr1, int addr2, int addr3) {
        Inet4Address inetAddress;
        String name = rootServerId + ".root-servers.net";
            try {
                inetAddress = (Inet4Address) InetAddress.getByAddress(name, new byte[] { (byte) addr0, (byte) addr1, (byte) addr2,
                        (byte) addr3 });
                IPV4_ROOT_SERVER_MAP.put(rootServerId, inetAddress);
            } catch (UnknownHostException e) {
                // This should never happen, if it does it's our fault!
                throw new RuntimeException(e);
            }

        return inetAddress;
    }

    private static Inet6Address rootServerInet6Address(char rootServerId, int addr0, int addr1, int addr2, int addr3, int addr4, int addr5, int addr6, int addr7) {
        Inet6Address inetAddress;
        String name = rootServerId + ".root-servers.net";
            try {
                inetAddress = (Inet6Address) InetAddress.getByAddress(name, new byte[]{
                        // @formatter:off
                        (byte) (addr0 >> 8), (byte) addr0, (byte) (addr1 >> 8), (byte) addr1,
                        (byte) (addr2 >> 8), (byte) addr2, (byte) (addr3 >> 8), (byte) addr3,
                        (byte) (addr4 >> 8), (byte) addr4, (byte) (addr5 >> 8), (byte) addr5,
                        (byte) (addr6 >> 8), (byte) addr6, (byte) (addr7 >> 8), (byte) addr7
                        // @formatter:on
                });
                IPV6_ROOT_SERVER_MAP.put(rootServerId, inetAddress);
            } catch (UnknownHostException e) {
                // This should never happen, if it does it's our fault!
                throw new RuntimeException(e);
            }
        return inetAddress;
    }

    @Override
    protected boolean isResponseCacheable(Question q, DNSMessage dnsMessage) {
        return dnsMessage.authoritativeAnswer;
    }

    @Override
    protected DNSMessage.Builder newQuestion(DNSMessage.Builder message) {
        message.setRecursionDesired(false);
        message.getEdnsBuilder().setUdpPayloadSize(dataSource.getUdpPayloadSize());
        return message;
    }

    private IpResultSet.Builder newIpResultSetBuilder() {
        return new IpResultSet.Builder(this.insecureRandom);
    }

    private static class IpResultSet {

        final List<InetAddress> addresses;

        private IpResultSet(List<InetAddress> ipv4Addresses, List<InetAddress> ipv6Addresses, Random random) {
            int size;
            switch (DEFAULT_IP_VERSION_SETTING) {
            case v4only:
                size = ipv4Addresses.size();
                break;
            case v6only:
                size = ipv6Addresses.size();
                break;
            case v4v6:
            case v6v4:
            default:
                size = ipv4Addresses.size() + ipv6Addresses.size();
                break;
            }

            if (size == 0) {
                // Fast-path in case there were no addresses, which could happen e.g., if the NS records where not
                // glued.
                addresses = Collections.emptyList();
            } else {
                // Shuffle the addresses first, so that the load is better balanced.
                if (DEFAULT_IP_VERSION_SETTING.v4) {
                    Collections.shuffle(ipv4Addresses, random);
                }
                if (DEFAULT_IP_VERSION_SETTING.v6) {
                    Collections.shuffle(ipv6Addresses, random);
                }

                List<InetAddress> addresses = new ArrayList<>(size);

                // Now add the shuffled addresses to the result list.
                switch (DEFAULT_IP_VERSION_SETTING) {
                case v4only:
                    addresses.addAll(ipv4Addresses);
                    break;
                case v6only:
                    addresses.addAll(ipv6Addresses);
                    break;
                case v4v6:
                    addresses.addAll(ipv4Addresses);
                    addresses.addAll(ipv6Addresses);
                    break;
                case v6v4:
                    addresses.addAll(ipv6Addresses);
                    addresses.addAll(ipv4Addresses);
                    break;
                }

                this.addresses = Collections.unmodifiableList(addresses);
            }
        }

        private static class Builder {
            private final Random random;
            private final List<InetAddress> ipv4Addresses = new ArrayList<>(8);
            private final List<InetAddress> ipv6Addresses = new ArrayList<>(8);

            private Builder(Random random) {
                this.random = random;
            }

            public IpResultSet build() {
                return new IpResultSet(ipv4Addresses, ipv6Addresses, random);
            }
        }
    }

    protected static void abortIfFatal(IOException ioException) throws IOException {
        if (ioException instanceof LoopDetected) {
            throw ioException;
        }
    }

}
