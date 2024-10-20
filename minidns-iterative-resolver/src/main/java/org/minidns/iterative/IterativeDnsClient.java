/*
 * Copyright 2015-2024 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.iterative;

import static org.minidns.constants.DnsRootServer.getIpv4RootServerById;
import static org.minidns.constants.DnsRootServer.getIpv6RootServerById;
import static org.minidns.constants.DnsRootServer.getRandomIpv4RootServer;
import static org.minidns.constants.DnsRootServer.getRandomIpv6RootServer;

import org.minidns.AbstractDnsClient;
import org.minidns.DnsCache;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsname.DnsName;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.iterative.IterativeClientException.LoopDetected;
import org.minidns.iterative.IterativeClientException.NotAuthoritativeNorGlueRrFound;
import org.minidns.record.A;
import org.minidns.record.AAAA;
import org.minidns.record.RRWithTarget;
import org.minidns.record.Record;
import org.minidns.record.Record.TYPE;
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
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;

public class IterativeDnsClient extends AbstractDnsClient {

    int maxSteps = 128;

    /**
     * Create a new recursive DNS client using the global default cache.
     */
    public IterativeDnsClient() {
        super();
    }

    /**
     * Create a new recursive DNS client with the given DNS cache.
     *
     * @param cache The backend DNS cache.
     */
    public IterativeDnsClient(DnsCache cache) {
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
    protected DnsQueryResult query(DnsMessage.Builder queryBuilder) throws IOException {
        DnsMessage q = queryBuilder.build();
        ResolutionState resolutionState = new ResolutionState(this);
        DnsQueryResult result = queryRecursive(resolutionState, q);
        return result;
    }

    private static InetAddress[] getTargets(Collection<? extends InternetAddressRR<? extends InetAddress>> primaryTargets,
            Collection<? extends InternetAddressRR<? extends InetAddress>> secondaryTargets) {
        InetAddress[] res = new InetAddress[2];

        for (InternetAddressRR<? extends InetAddress> arr : primaryTargets) {
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

        for (InternetAddressRR<? extends InetAddress> arr : secondaryTargets) {
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

    private DnsQueryResult queryRecursive(ResolutionState resolutionState, DnsMessage q) throws IOException {
        InetAddress primaryTarget = null, secondaryTarget = null;

        Question question = q.getQuestion();
        DnsName parent = question.name.getParent();

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

        DnsName authoritativeZone = parent;
        if (primaryTarget == null) {
            authoritativeZone = DnsName.ROOT;
            switch (ipVersionSetting) {
            case v4only:
                primaryTarget = getRandomIpv4RootServer(insecureRandom);
                break;
            case v6only:
                primaryTarget = getRandomIpv6RootServer(insecureRandom);
                break;
            case v4v6:
                primaryTarget = getRandomIpv4RootServer(insecureRandom);
                secondaryTarget = getRandomIpv6RootServer(insecureRandom);
                break;
            case v6v4:
                primaryTarget = getRandomIpv6RootServer(insecureRandom);
                secondaryTarget = getRandomIpv4RootServer(insecureRandom);
                break;
            }
        }

        List<IOException> ioExceptions = new ArrayList<>();

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

    private DnsQueryResult queryRecursive(ResolutionState resolutionState, DnsMessage q, InetAddress address, DnsName authoritativeZone) throws IOException {
        resolutionState.recurse(address, q);

        DnsQueryResult dnsQueryResult = query(q, address);

        DnsMessage resMessage = dnsQueryResult.response;
        if (resMessage.authoritativeAnswer) {
            return dnsQueryResult;
        }

        if (cache != null) {
            cache.offer(q, dnsQueryResult, authoritativeZone);
        }

        List<Record<? extends Data>> authorities = resMessage.copyAuthority();

        List<IOException> ioExceptions = new ArrayList<>();

        // Glued NS first
        for (Iterator<Record<? extends Data>> iterator = authorities.iterator(); iterator.hasNext(); ) {
            Record<NS> record = iterator.next().ifPossibleAs(NS.class);
            if (record == null) {
                iterator.remove();
                continue;
            }
            DnsName name = record.payloadData.target;
            IpResultSet gluedNs = searchAdditional(resMessage, name);
            for (Iterator<InetAddress> addressIterator = gluedNs.addresses.iterator(); addressIterator.hasNext(); ) {
                InetAddress target = addressIterator.next();
                DnsQueryResult recursive = null;
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
            DnsName name = ((NS) record.payloadData).target;

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
                DnsQueryResult recursive = null;
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

        // Reaching this point means we did not receive an authoritative answer, nor
        // where we able to find glue records or the IPs of the next nameservers.
        throw new NotAuthoritativeNorGlueRrFound(q, dnsQueryResult, authoritativeZone);
    }

    private IpResultSet resolveIpRecursive(ResolutionState resolutionState, DnsName name) throws IOException {
        IpResultSet.Builder res = newIpResultSetBuilder();

        if (ipVersionSetting.v4) {
            // TODO Try to retrieve A records for name out from cache.
            Question question = new Question(name, TYPE.A);
            final DnsMessage query = getQueryFor(question);
            DnsQueryResult aDnsQueryResult = queryRecursive(resolutionState, query);
            // TODO: queryRecurisve() should probably never return null. Verify that and then remove the follwing null check.
            DnsMessage aMessage = aDnsQueryResult != null ? aDnsQueryResult.response : null;
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
            final DnsMessage query = getQueryFor(question);
            DnsQueryResult aDnsQueryResult = queryRecursive(resolutionState, query);
            // TODO: queryRecurisve() should probably never return null. Verify that and then remove the follwing null check.
            DnsMessage aMessage = aDnsQueryResult != null ? aDnsQueryResult.response : null;
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
    private IpResultSet searchAdditional(DnsMessage message, DnsName name) {
        IpResultSet.Builder res = newIpResultSetBuilder();
        for (Record<? extends Data> record : message.additionalSection) {
            if (!record.name.equals(name)) {
                continue;
            }
            switch (record.type) {
            case A:
                res.ipv4Addresses.add(inetAddressFromRecord(name.ace, (A) record.payloadData));
                break;
            case AAAA:
                res.ipv6Addresses.add(inetAddressFromRecord(name.ace, (AAAA) record.payloadData));
                break;
            default:
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
        Inet4Address ipv4Root = getIpv4RootServerById(rootServerId);
        Inet6Address ipv6Root = getIpv6RootServerById(rootServerId);
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

    @Override
    protected boolean isResponseCacheable(Question q, DnsQueryResult result) {
        return result.response.authoritativeAnswer;
    }

    @Override
    protected DnsMessage.Builder newQuestion(DnsMessage.Builder message) {
        message.setRecursionDesired(false);
        message.getEdnsBuilder().setUdpPayloadSize(dataSource.getUdpPayloadSize());
        return message;
    }

    private IpResultSet.Builder newIpResultSetBuilder() {
        return new IpResultSet.Builder(this.insecureRandom);
    }

    private static final class IpResultSet {

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

        private static final class Builder {
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
