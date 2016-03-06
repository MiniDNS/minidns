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
package de.measite.minidns.recursive;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSCache;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.NS;
import de.measite.minidns.util.MultipleIoException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;

public class RecursiveDNSClient extends AbstractDNSClient {

    protected static final InetAddress[] ROOT_SERVERS = new InetAddress[]{
        rootServerInetAddress("a.root-servers.net", new int[]{198,  41,   0,   4}),
        rootServerInetAddress("b.root-servers.net", new int[]{192, 228,  79, 201}),
        rootServerInetAddress("c.root-servers.net", new int[]{192,  33,   4,  12}),
        rootServerInetAddress("d.root-servers.net", new int[]{199,   7,  91 , 13}),
        rootServerInetAddress("e.root-servers.net", new int[]{192, 203, 230,  10}),
        rootServerInetAddress("f.root-servers.net", new int[]{192,   5,   5, 241}),
        rootServerInetAddress("g.root-servers.net", new int[]{192, 112,  36,   4}),
        rootServerInetAddress("h.root-servers.net", new int[]{128,  63,   2,  53}),
        rootServerInetAddress("i.root-servers.net", new int[]{192,  36, 148,  17}),
        rootServerInetAddress("j.root-servers.net", new int[]{192,  58, 128,  30}),
        rootServerInetAddress("k.root-servers.net", new int[]{193,   0,  14, 129}),
        rootServerInetAddress("l.root-servers.net", new int[]{199,   7,  83,  42}),
        rootServerInetAddress("m.root-servers.net", new int[]{202,  12,  27,  33}),
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
     * @param q The question section of the DNS query.
     * @return The response (or null on timeout/error).
     * @throws IOException if an IO error occurs.
     */
    @Override
    public DNSMessage query(Question q) throws IOException {
        RecursionState recursionState = new RecursionState(this);
        DNSMessage message = queryRecursive(recursionState, q);
        if (message == null) return null;
        // TODO: restrict to real answer or accept non-answers?
        return message;
    }

    private DNSMessage queryRecursive(RecursionState recursionState, Question q) throws IOException {
        InetAddress target = ROOT_SERVERS[random.nextInt(ROOT_SERVERS.length)];
        return queryRecursive(recursionState, q, target);
    }

    private DNSMessage queryRecursive(RecursionState recursionState, Question q, InetAddress address) throws IOException {
        recursionState.recurse(address, q);

        DNSMessage resMessage = query(q, address);

        if (resMessage == null || resMessage.isAuthoritativeAnswer()) {
            return resMessage;
        }
        List<Record> authorities = new ArrayList<>(Arrays.asList(resMessage.getNameserverRecords()));

        List<IOException> ioExceptions = new LinkedList<>();

        // Glued NS first
        for (Iterator<Record> iterator = authorities.iterator(); iterator.hasNext(); ) {
            Record record = iterator.next();
            if (record.type != TYPE.NS) {
                iterator.remove();
                continue;
            }
            String name = ((NS) record.payloadData).name;
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
            String name = ((NS) record.payloadData).name;
            if (!q.name.equals(name) || q.type != TYPE.A) {
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

    private IpResultSet resolveIpRecursive(RecursionState recursionState, String name) throws IOException {
        IpResultSet res = new IpResultSet();

        if (ipVersionSetting != IpVersionSetting.v6only) {
            Question question = new Question(name, TYPE.A);
            DNSMessage aMessage = queryRecursive(recursionState, question);
            if (aMessage != null) {
                for (Record answer : aMessage.getAnswers()) {
                    if (answer.isAnswer(question)) {
                        InetAddress inetAddress = inetAddressFromRecord(name, (A) answer.payloadData);
                        res.ipv4Addresses.add(inetAddress);
                    } else if (answer.type == TYPE.CNAME && answer.name.equals(name)) {
                        return resolveIpRecursive(recursionState, ((CNAME) answer.payloadData).name);
                    }
                }
            }
        }

        if (ipVersionSetting != IpVersionSetting.v4only) {
            Question question = new Question(name, TYPE.AAAA);
            DNSMessage aMessage = queryRecursive(recursionState, question);
            if (aMessage != null) {
                for (Record answer : aMessage.getAnswers()) {
                    if (answer.isAnswer(question)) {
                        InetAddress inetAddress = inetAddressFromRecord(name, (AAAA) answer.payloadData);
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
    private static IpResultSet searchAdditional(DNSMessage message, String name) {
        IpResultSet res = new IpResultSet();
        for (Record record : message.getAdditionalResourceRecords()) {
            if (!record.name.equals(name)) {
                continue;
            }
            switch (record.type) {
            case A:
                res.ipv4Addresses.add(inetAddressFromRecord(name, ((A) record.payloadData)));
                break;
            case AAAA:
                res.ipv6Addresses.add(inetAddressFromRecord(name, ((AAAA) record.payloadData)));
                break;
            }
        }
        return res;
    }

    private static InetAddress inetAddressFromRecord(String name, A recordPayload) {
        try {
            return InetAddress.getByAddress(name, recordPayload.ip);
        } catch (UnknownHostException e) {
            // This will never happen
            throw new RuntimeException(e);
        }
    }

    private static InetAddress inetAddressFromRecord(String name, AAAA recordPayload) {
        try {
            return InetAddress.getByAddress(name, recordPayload.ip);
        } catch (UnknownHostException e) {
            // This will never happen
            throw new RuntimeException(e);
        }
    }

    private static InetAddress rootServerInetAddress(String name, int[] addr) {
        try {
            return InetAddress.getByAddress(name, new byte[]{(byte) addr[0], (byte) addr[1], (byte) addr[2], (byte) addr[3]});
        } catch (UnknownHostException e) {
            // This should never happen, if it does it's our fault!
            throw new RuntimeException(e);
        }
    }

    @Override
    protected boolean isResponseCacheable(Question q, DNSMessage dnsMessage) {
        return dnsMessage.isAuthoritativeAnswer();
    }

    @Override
    protected DNSMessage newQuestion(DNSMessage message) {
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
}
