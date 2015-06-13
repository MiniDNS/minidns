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

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.record.A;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.NS;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;

public class RecursiveDNSClient extends AbstractDNSClient {

    private static final InetAddress[] ROOT_SERVERS;
    private int maxDepth = 128;

    static {
        ROOT_SERVERS = new InetAddress[]{
                rootServerInetAddress("a.root-servers.net", new int[]{198, 41, 0, 4}),
                rootServerInetAddress("b.root-servers.net", new int[]{192, 228, 79, 201}),
                rootServerInetAddress("c.root-servers.net", new int[]{192, 33, 4, 12}),
                rootServerInetAddress("d.root-servers.net", new int[]{199, 7, 91, 13}),
                rootServerInetAddress("e.root-servers.net", new int[]{192, 203, 230, 10}),
                rootServerInetAddress("f.root-servers.net", new int[]{192, 5, 5, 241}),
                rootServerInetAddress("g.root-servers.net", new int[]{192, 112, 36, 4}),
                rootServerInetAddress("h.root-servers.net", new int[]{128, 63, 2, 53}),
                rootServerInetAddress("i.root-servers.net", new int[]{192, 36, 148, 17}),
                rootServerInetAddress("j.root-servers.net", new int[]{192, 58, 128, 30}),
                rootServerInetAddress("k.root-servers.net", new int[]{193, 0, 14, 129}),
                rootServerInetAddress("l.root-servers.net", new int[]{199, 7, 83, 42}),
                rootServerInetAddress("m.root-servers.net", new int[]{202, 12, 27, 33}),
        };
    }

    public RecursiveDNSClient(DNSCache dnsCache) {
        super(dnsCache);
    }

    public RecursiveDNSClient(Map<Question, DNSMessage> cache) {
        super(cache);
    }

    @Override
    public DNSMessage query(Question q) {
        DNSMessage message = queryRecursive(0, q);
        if (message == null) return null;
        // TODO: restrict to real answer or accept non-answers?
        for (Record answer : message.answers) {
            if (answer.isAnswer(q)) {
                return message;
            }
        }
        return null;
    }

    public DNSMessage queryRecursive(int depth, Question q) {
        InetAddress target = ROOT_SERVERS[random.nextInt(ROOT_SERVERS.length)];
        return queryRecursive(depth, q, target);
    }

    private DNSMessage queryRecursive(int depth, Question q, InetAddress address) {
        if (depth > maxDepth) return null;
        DNSMessage resMessage;
        try {
            resMessage = query(q, address);
        } catch (IOException e) {
            return null;
        }
        if (resMessage == null || resMessage.authoritativeAnswer) {
            return resMessage;
        }
        for (Record record : resMessage.nameserverRecords) {
            if (record.type == TYPE.NS) {
                String name = ((NS) record.payloadData).name;
                InetAddress target = searchAdditional(resMessage, name);
                if (target == null && !(q.name.equals(name) && q.type == TYPE.A)) {
                    target = resolveIpRecursive(depth + 1, name);
                }
                if (target != null) {
                    DNSMessage recursive = queryRecursive(depth + 1, q, target);
                    if (recursive != null) {
                        return recursive;
                    }
                }
            }
        }
        return null;
    }

    private InetAddress resolveIpRecursive(int depth, String name) {
        // TODO: IPv6?
        Question question = new Question(name, TYPE.A);
        DNSMessage aMessage = queryRecursive(depth + 1, question);
        if (aMessage != null) {
            for (Record answer : aMessage.answers) {
                if (answer.isAnswer(question)) {
                    return inetAddressFromRecord(name, (A) answer.payloadData);
                } else if (answer.type == TYPE.CNAME && answer.name.equals(name)) {
                    return resolveIpRecursive(depth + 1, ((CNAME) answer.payloadData).name);
                }
            }
        }
        return null;
    }

    private InetAddress searchAdditional(DNSMessage message, String name) {
        for (Record record : message.additionalResourceRecords) {
            // TODO: IPv6?
            if (record.type == TYPE.A && record.name.equals(name)) {
                return inetAddressFromRecord(name, ((A) record.payloadData));
            }
        }
        return null;
    }

    private static InetAddress inetAddressFromRecord(String name, A recordPayload) {
        try {
            return InetAddress.getByAddress(name, recordPayload.ip);
        } catch (UnknownHostException ignored) {
            // This will never happen
            return null;
        }
    }

    private static InetAddress rootServerInetAddress(String name, int[] addr) {
        try {
            return InetAddress.getByAddress(name, new byte[]{(byte) addr[0], (byte) addr[1], (byte) addr[2], (byte) addr[3]});
        } catch (Exception e) {
            // This should never happen, if it does it's our fault!
            throw new RuntimeException(e);
        }
    }

    @Override
    protected DNSMessage buildMessage(Question question) {
        DNSMessage message = new DNSMessage();
        message.setQuestions(question);
        message.setRecursionDesired(false);
        message.setId(random.nextInt());
        message.setOptPseudoRecord(dataSource.getUdpPayloadSize(), 0);
        return message;
    }
}
