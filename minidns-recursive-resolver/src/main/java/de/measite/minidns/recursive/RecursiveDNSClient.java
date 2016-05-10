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
import de.measite.minidns.record.NS;
import de.measite.minidns.recursive.RecursiveClientException.LoopDetected;
import de.measite.minidns.util.MultipleIoException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;

public class RecursiveDNSClient extends AbstractDNSClient {

    protected static final InetAddress[] IPV4_ROOT_SERVERS = new InetAddress[] {
        rootServerInetAddress('a', new int[]{198,  41,   0,   4}),
        rootServerInetAddress('b', new int[]{192, 228,  79, 201}),
        rootServerInetAddress('c', new int[]{192,  33,   4,  12}),
        rootServerInetAddress('d', new int[]{199,   7,  91 , 13}),
        rootServerInetAddress('e', new int[]{192, 203, 230,  10}),
        rootServerInetAddress('f', new int[]{192,   5,   5, 241}),
        rootServerInetAddress('g', new int[]{192, 112,  36,   4}),
        rootServerInetAddress('h', new int[]{128,  63,   2,  53}),
        rootServerInetAddress('i', new int[]{192,  36, 148,  17}),
        rootServerInetAddress('j', new int[]{192,  58, 128,  30}),
        rootServerInetAddress('k', new int[]{193,   0,  14, 129}),
        rootServerInetAddress('l', new int[]{199,   7,  83,  42}),
        rootServerInetAddress('m', new int[]{202,  12,  27,  33}),
    };

    protected static final InetAddress[] IPV6_ROOT_SERVERS = new InetAddress[] {
        rootServerInetAddress('a', new int[]{0x2001, 0x503, 0xba3e, 0x0, 0x0, 0x0, 0x2, 0x30}),
        rootServerInetAddress('b', new int[]{0x2001, 0x500, 0x84, 0x0, 0x0, 0x0, 0x0, 0xb}),
        rootServerInetAddress('c', new int[]{0x2001, 0x500, 0x2, 0x0, 0x0, 0x0, 0x0, 0xc}),
        rootServerInetAddress('d', new int[]{0x2001, 0x500, 0x2d, 0x0, 0x0, 0x0, 0x0, 0xd}),
        rootServerInetAddress('f', new int[]{0x2001, 0x500, 0x2f, 0x0, 0x0, 0x0, 0x0, 0xf}),
        rootServerInetAddress('h', new int[]{0x2001, 0x500, 0x1, 0x0, 0x0, 0x0, 0x0, 0x53}),
        rootServerInetAddress('i', new int[]{0x2001, 0x7fe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53}),
        rootServerInetAddress('j', new int[]{0x2001, 0x503, 0xc27, 0x0, 0x0, 0x0, 0x2, 0x30}),
        rootServerInetAddress('l', new int[]{0x2001, 0x500, 0x3, 0x0, 0x0, 0x0, 0x0, 0x42}),
        rootServerInetAddress('m', new int[]{0x2001, 0xdc3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x35}),
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
        if (message == null) return null;
        // TODO: restrict to real answer or accept non-answers?
        return message;
    }

    private InetAddress getRandomIpv4RootServer() {
        return IPV4_ROOT_SERVERS[insecureRandom.nextInt(IPV4_ROOT_SERVERS.length)];
    }

    private InetAddress getRandomIpv6RootServer() {
        return IPV6_ROOT_SERVERS[insecureRandom.nextInt(IPV6_ROOT_SERVERS.length)];
    }

    private DNSMessage queryRecursive(RecursionState recursionState, DNSMessage q) throws IOException {
        InetAddress primaryTarget = null, secondaryTarget = null;
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

        List<IOException> ioExceptions = new LinkedList<>();

        try {
            return queryRecursive(recursionState, q, primaryTarget);
        } catch (IOException ioException) {
            abortIfFatal(ioException);
            ioExceptions.add(ioException);
        }

        if (secondaryTarget != null) {
            try {
                return queryRecursive(recursionState, q, secondaryTarget);
            } catch (IOException ioException) {
                ioExceptions.add(ioException);
            }
        }

        MultipleIoException.throwIfRequired(ioExceptions);
        return null;
    }

    private DNSMessage queryRecursive(RecursionState recursionState, DNSMessage q, InetAddress address) throws IOException {
        recursionState.recurse(address, q);

        DNSMessage resMessage = query(q, address);

        if (resMessage == null || resMessage.authoritativeAnswer) {
            return resMessage;
        }
        List<Record> authorities = resMessage.copyNameserverRecords();

        List<IOException> ioExceptions = new LinkedList<>();

        // Glued NS first
        for (Iterator<Record> iterator = authorities.iterator(); iterator.hasNext(); ) {
            Record record = iterator.next();
            if (record.type != TYPE.NS) {
                iterator.remove();
                continue;
            }
            DNSName name = ((NS) record.payloadData).name;
            IpResultSet gluedNs = searchAdditional(resMessage, name);
            for (InetAddress target : gluedNs.getAddresses()) {
                DNSMessage recursive = null;
                try {
                    recursive = queryRecursive(recursionState, q, target);
                } catch (IOException e) {
                   LOGGER.log(Level.FINER, "Exception while recursing", e);
                   recursionState.decrementSteps();
                   ioExceptions.add(e);
                   iterator.remove();
                   continue;
                }
                return recursive;
            }
        }

        // Try non-glued NS
        for (Record record : authorities) {
            final Question question = q.getQuestion();
            DNSName name = ((NS) record.payloadData).name;
            if (!question.name.equals(name) || question.type != TYPE.A) {
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

                for (InetAddress target : res.getAddresses()) {
                    DNSMessage recursive = null;
                    try {
                        recursive = queryRecursive(recursionState, q, target);
                    } catch (IOException e) {
                        recursionState.decrementSteps();
                        ioExceptions.add(e);
                        continue;
                    }
                    return recursive;
                }
            }
        }

        MultipleIoException.throwIfRequired(ioExceptions);

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
        IpResultSet res = new IpResultSet();

        if (ipVersionSetting != IpVersionSetting.v6only) {
            Question question = new Question(name, TYPE.A);
            final DNSMessage query = getQueryFor(question);
            DNSMessage aMessage = queryRecursive(recursionState, query);
            if (aMessage != null) {
                for (Record answer : aMessage.answers) {
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
            Question question = new Question(name, TYPE.AAAA);
            final DNSMessage query = getQueryFor(question);
            DNSMessage aMessage = queryRecursive(recursionState, query);
            if (aMessage != null) {
                for (Record answer : aMessage.answers) {
                    if (answer.isAnswer(question)) {
                        InetAddress inetAddress = inetAddressFromRecord(name.ace, (AAAA) answer.payloadData);
                        res.ipv6Addresses.add(inetAddress);
                    } else if (answer.type == TYPE.CNAME && answer.name.equals(name)) {
                        return resolveIpRecursive(recursionState, ((CNAME) answer.payloadData).name);
                    }
                }
            }
        }

        return res;
    }

    @SuppressWarnings("incomplete-switch")
    private static IpResultSet searchAdditional(DNSMessage message, DNSName name) {
        IpResultSet res = new IpResultSet();
        for (Record record : message.additionalResourceRecords) {
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
        return res;
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

    private static InetAddress rootServerInetAddress(char rootServerId, int[] addr) {
        String name = rootServerId + ".root-servers.net";
        if (addr.length == 4) {
            try {
                return InetAddress.getByAddress(name, new byte[] { (byte) addr[0], (byte) addr[1], (byte) addr[2],
                        (byte) addr[3] });
            } catch (UnknownHostException e) {
                // This should never happen, if it does it's our fault!
                throw new RuntimeException(e);
            }
        } else if (addr.length == 8) {
            try {
                return InetAddress.getByAddress(name, new byte[]{
                        // @formatter:off
                        (byte) (addr[0] >> 8), (byte) addr[0], (byte) (addr[1] >> 8), (byte) addr[1],
                        (byte) (addr[2] >> 8), (byte) addr[2], (byte) (addr[3] >> 8), (byte) addr[3],
                        (byte) (addr[4] >> 8), (byte) addr[4], (byte) (addr[5] >> 8), (byte) addr[5],
                        (byte) (addr[6] >> 8), (byte) addr[6], (byte) (addr[7] >> 8), (byte) addr[7]
                        // @formatter:on
                });
            } catch (UnknownHostException e) {
                // This should never happen, if it does it's our fault!
                throw new RuntimeException(e);
            }
        } else {
            throw new IllegalArgumentException();
        }
    }

    @Override
    protected boolean isResponseCacheable(Question q, DNSMessage dnsMessage) {
        return dnsMessage.authoritativeAnswer;
    }

    @Override
    protected DNSMessage.Builder newQuestion(DNSMessage.Builder message) {
        message.setRecursionDesired(false);
        message.setOptPseudoRecord(dataSource.getUdpPayloadSize(), 0);
        return message;
    }

    private static class IpResultSet {
        final List<InetAddress> ipv4Addresses = new LinkedList<>();
        final List<InetAddress> ipv6Addresses = new LinkedList<>();

        List<InetAddress> getAddresses() {
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

            List<InetAddress> addresses = new ArrayList<>(size);

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
            return addresses;
        }
    }

    protected static void abortIfFatal(IOException ioException) throws IOException {
        if (ioException instanceof LoopDetected) {
            throw ioException;
        }
    }
}
