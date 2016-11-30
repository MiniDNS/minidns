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
package de.measite.minidns.recursive;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSCache;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.DNSName;
import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.InternetAddressRR;
import de.measite.minidns.record.NS;
import de.measite.minidns.recursive.RecursiveClientException.LoopDetected;
import de.measite.minidns.util.MultipleIoException;

import java.io.IOException;
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

public class RecursiveDNSClient extends AbstractDNSClient {

    private static final Map<Character, InetAddress> IPV4_ROOT_SERVER_MAP = new HashMap<>();

    private static final Map<Character, InetAddress> IPV6_ROOT_SERVER_MAP = new HashMap<>();

    protected static final InetAddress[] IPV4_ROOT_SERVERS = new InetAddress[] {
        rootServerInetAddress('a', new int[]{198,  41,   0,   4}),
        rootServerInetAddress('b', new int[]{192, 228,  79, 201}),
        rootServerInetAddress('c', new int[]{192,  33,   4,  12}),
        rootServerInetAddress('d', new int[]{199,   7,  91 , 13}),
        rootServerInetAddress('e', new int[]{192, 203, 230,  10}),
        rootServerInetAddress('f', new int[]{192,   5,   5, 241}),
        rootServerInetAddress('g', new int[]{192, 112,  36,   4}),
        rootServerInetAddress('h', new int[]{198,  97, 190,  53}),
        rootServerInetAddress('i', new int[]{192,  36, 148,  17}),
        rootServerInetAddress('j', new int[]{192,  58, 128,  30}),
        rootServerInetAddress('k', new int[]{193,   0,  14, 129}),
        rootServerInetAddress('l', new int[]{199,   7,  83,  42}),
        rootServerInetAddress('m', new int[]{202,  12,  27,  33}),
    };

    protected static final InetAddress[] IPV6_ROOT_SERVERS = new InetAddress[] {
        rootServerInetAddress('a', new int[]{0x2001, 0x0503, 0xba3e, 0x0000, 0x0000, 0x000, 0x0002, 0x0030}),
        rootServerInetAddress('b', new int[]{0x2001, 0x0500, 0x0084, 0x0000, 0x0000, 0x000, 0x0000, 0x000b}),
        rootServerInetAddress('c', new int[]{0x2001, 0x0500, 0x0002, 0x0000, 0x0000, 0x000, 0x0000, 0x000c}),
        rootServerInetAddress('d', new int[]{0x2001, 0x0500, 0x002d, 0x0000, 0x0000, 0x000, 0x0000, 0x000d}),
        rootServerInetAddress('f', new int[]{0x2001, 0x0500, 0x002f, 0x0000, 0x0000, 0x000, 0x0000, 0x000f}),
        rootServerInetAddress('h', new int[]{0x2001, 0x0500, 0x0001, 0x0000, 0x0000, 0x000, 0x0000, 0x0053}),
        rootServerInetAddress('i', new int[]{0x2001, 0x07fe, 0x0000, 0x0000, 0x0000, 0x000, 0x0000, 0x0053}),
        rootServerInetAddress('j', new int[]{0x2001, 0x0503, 0x0c27, 0x0000, 0x0000, 0x000, 0x0002, 0x0030}),
        rootServerInetAddress('l', new int[]{0x2001, 0x0500, 0x0003, 0x0000, 0x0000, 0x000, 0x0000, 0x0042}),
        rootServerInetAddress('m', new int[]{0x2001, 0x0dc3, 0x0000, 0x0000, 0x0000, 0x000, 0x0000, 0x0035}),
    };

    int maxSteps = 128;

    /**
     * Create a new recursive DNS client using the global default cache.
     */
    public RecursiveDNSClient() {
        super();
    }

    /**
     * Create a new recursive DNS client with the given DNS cache.
     *
     * @param cache The backend DNS cache.
     */
    public RecursiveDNSClient(DNSCache cache) {
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
        RecursionState recursionState = new RecursionState(this);
        DNSMessage message = queryRecursive(recursionState, q);
        return message;
    }

    private InetAddress getRandomIpv4RootServer() {
        return IPV4_ROOT_SERVERS[insecureRandom.nextInt(IPV4_ROOT_SERVERS.length)];
    }

    private InetAddress getRandomIpv6RootServer() {
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

    private DNSMessage queryRecursive(RecursionState recursionState, DNSMessage q) throws IOException {
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
            return queryRecursive(recursionState, q, primaryTarget, authoritativeZone);
        } catch (IOException ioException) {
            abortIfFatal(ioException);
            ioExceptions.add(ioException);
        }

        if (secondaryTarget != null) {
            try {
                return queryRecursive(recursionState, q, secondaryTarget, authoritativeZone);
            } catch (IOException ioException) {
                ioExceptions.add(ioException);
            }
        }

        MultipleIoException.throwIfRequired(ioExceptions);
        return null;
    }

    private DNSMessage queryRecursive(RecursionState recursionState, DNSMessage q, InetAddress address, DNSName authoritativeZone) throws IOException {
        recursionState.recurse(address, q);

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
            DNSName name = ((NS) record.payloadData).name;
            IpResultSet gluedNs = searchAdditional(resMessage, name);
            for (Iterator<InetAddress> addressIterator = gluedNs.addresses.iterator(); addressIterator.hasNext(); ) {
                InetAddress target = addressIterator.next();
                DNSMessage recursive = null;
                try {
                    recursive = queryRecursive(recursionState, q, target, record.name);
                } catch (IOException e) {
                   abortIfFatal(e);
                   LOGGER.log(Level.FINER, "Exception while recursing", e);
                   recursionState.decrementSteps();
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
            DNSName name = ((NS) record.payloadData).name;

            // Loop prevention: If this non-glued NS equals the name we question for and if the question is about a A or
            // AAAA RR, then we should not continue here as it would result in an endless loop.
            if (question.name.equals(name) && (question.type == TYPE.A || question.type == TYPE.AAAA))
                continue;

            IpResultSet res = null;
            try {
                res = resolveIpRecursive(recursionState, name);
            } catch (IOException e) {
                recursionState.decrementSteps();
                ioExceptions.add(e);
            }
            if (res == null) {
                continue;
            }

            for (InetAddress target : res.addresses) {
                DNSMessage recursive = null;
                try {
                    recursive = queryRecursive(recursionState, q, target, record.name);
                } catch (IOException e) {
                    recursionState.decrementSteps();
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

    public enum IpVersionSetting {
        v4only,
        v6only,
        v4v6,
        v6v4,
        ;
    }

    private static IpVersionSetting ipVersionSetting = IpVersionSetting.v4v6;

    public static void setPreferedIpVersion(IpVersionSetting preferedIpVersion) {
        if (preferedIpVersion == null) {
            throw new IllegalArgumentException();
        }
        RecursiveDNSClient.ipVersionSetting = preferedIpVersion;
    }

    private IpResultSet resolveIpRecursive(RecursionState recursionState, DNSName name) throws IOException {
        IpResultSet.Builder res = newIpResultSetBuilder();

        if (ipVersionSetting != IpVersionSetting.v6only) {
            // TODO Try to retrieve A records for name out from cache.
            Question question = new Question(name, TYPE.A);
            final DNSMessage query = getQueryFor(question);
            DNSMessage aMessage = queryRecursive(recursionState, query);
            if (aMessage != null) {
                for (Record<? extends Data> answer : aMessage.answerSection) {
                    if (answer.isAnswer(question)) {
                        InetAddress inetAddress = inetAddressFromRecord(name.ace, (A) answer.payloadData);
                        res.ipv4Addresses.add(inetAddress);
                    } else if (answer.type == TYPE.CNAME && answer.name.equals(name)) {
                        return resolveIpRecursive(recursionState, ((CNAME) answer.payloadData).name);
                    }
                }
            }
        }

        if (ipVersionSetting != IpVersionSetting.v4only) {
            // TODO Try to retrieve AAAA records for name out from cache.
            Question question = new Question(name, TYPE.AAAA);
            final DNSMessage query = getQueryFor(question);
            DNSMessage aMessage = queryRecursive(recursionState, query);
            if (aMessage != null) {
                for (Record<? extends Data> answer : aMessage.answerSection) {
                    if (answer.isAnswer(question)) {
                        InetAddress inetAddress = inetAddressFromRecord(name.ace, (AAAA) answer.payloadData);
                        res.ipv6Addresses.add(inetAddress);
                    } else if (answer.type == TYPE.CNAME && answer.name.equals(name)) {
                        return resolveIpRecursive(recursionState, ((CNAME) answer.payloadData).name);
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
        return getRootServer(rootServerId, ipVersionSetting);
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

    private static InetAddress rootServerInetAddress(char rootServerId, int[] addr) {
        InetAddress inetAddress;
        String name = rootServerId + ".root-servers.net";
        if (addr.length == 4) {
            try {
                inetAddress = InetAddress.getByAddress(name, new byte[] { (byte) addr[0], (byte) addr[1], (byte) addr[2],
                        (byte) addr[3] });
                IPV4_ROOT_SERVER_MAP.put(rootServerId, inetAddress);
            } catch (UnknownHostException e) {
                // This should never happen, if it does it's our fault!
                throw new RuntimeException(e);
            }
        } else if (addr.length == 8) {
            try {
                inetAddress = InetAddress.getByAddress(name, new byte[]{
                        // @formatter:off
                        (byte) (addr[0] >> 8), (byte) addr[0], (byte) (addr[1] >> 8), (byte) addr[1],
                        (byte) (addr[2] >> 8), (byte) addr[2], (byte) (addr[3] >> 8), (byte) addr[3],
                        (byte) (addr[4] >> 8), (byte) addr[4], (byte) (addr[5] >> 8), (byte) addr[5],
                        (byte) (addr[6] >> 8), (byte) addr[6], (byte) (addr[7] >> 8), (byte) addr[7]
                        // @formatter:on
                });
                IPV6_ROOT_SERVER_MAP.put(rootServerId, inetAddress);
            } catch (UnknownHostException e) {
                // This should never happen, if it does it's our fault!
                throw new RuntimeException(e);
            }
        } else {
            throw new IllegalArgumentException();
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
            switch (ipVersionSetting) {
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
                switch (ipVersionSetting) {
                case v4only:
                case v4v6:
                case v6v4:
                    Collections.shuffle(ipv4Addresses, random);
                    break;
                default:
                    break;
                }
                switch (ipVersionSetting) {
                case v4v6:
                case v6v4:
                case v6only:
                    Collections.shuffle(ipv6Addresses, random);
                    break;
                default:
                    break;
                }

                List<InetAddress> addresses = new ArrayList<>(size);

                // Now add the shuffled addresses to the result list.
                switch (ipVersionSetting) {
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
