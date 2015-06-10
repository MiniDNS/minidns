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
    public RecursiveDNSClient(DNSCache dnsCache) {
        super(dnsCache);
    }

    public RecursiveDNSClient(Map<Question, DNSMessage> cache) {
        super(cache);
    }

    @Override
    public DNSMessage query(Question q) {
        try {
            // TODO: add more root servers https://www.iana.org/domains/root/servers
            InetAddress target = InetAddress.getByAddress("a.root-servers.net", new byte[]{(byte) 198, 41, 0, 4});
            return queryRecursive(q, target);
        } catch (IOException e) {
            return null;
        }
    }

    public DNSMessage queryRecursive(Question q, InetAddress address) throws IOException {
        DNSMessage resMessage = query(q, address);
        if (resMessage == null || resMessage.authoritativeAnswer) {
            return resMessage;
        }
        for (Record record : resMessage.nameserverRecords) {
            if (record.type == TYPE.NS) {
                String name = ((NS) record.payloadData).name;
                InetAddress target = searchAdditional(resMessage, name);
                if (target == null) {
                    target = resolveIpRecursive(name);
                }
                if (target != null) {
                    DNSMessage recursive = queryRecursive(q, target);
                    if (recursive != null) {
                        return recursive;
                    }
                }
            }
        }
        return null;
    }

    private InetAddress resolveIpRecursive(String name) throws UnknownHostException {
        Question question = new Question(name, TYPE.A);
        DNSMessage aMessage = query(question);
        if (aMessage != null) {
            for (Record answer : aMessage.answers) {
                if (answer.isAnswer(question)) {
                    return InetAddress.getByAddress(name, ((A) answer.payloadData).ip);
                } else if (answer.type == TYPE.CNAME && answer.name.equals(name)) {
                    return resolveIpRecursive(((CNAME) answer.payloadData).name);
                }
            }
        }
        return null;
    }

    private InetAddress searchAdditional(DNSMessage message, String name) throws UnknownHostException {
        for (Record record : message.additionalResourceRecords) {
            // TODO: IPv6?
            if (record.type == TYPE.A && record.name.equals(name)) {
                return InetAddress.getByAddress(name, ((A) record.payloadData).ip);
            }
        }
        return null;
    }

    @Override
    public DNSMessage query(Question q, InetAddress address, int port) throws IOException {
        System.out.println("Q: " + q + " @ " + address);
        // See if we have the answer to this question already cached
        DNSMessage dnsMessage = (cache == null) ? null : cache.get(q);
        if (dnsMessage != null) {
            return dnsMessage;
        }

        DNSMessage message = new DNSMessage();
        message.setQuestions(new Question[]{q});
        message.setRecursionDesired(false);
        message.setId(random.nextInt());
        message.setOptPseudoRecord(Math.min(getUdpPayloadSize(), bufferSize), 0);

        dnsMessage = queryUdp(address, port, message);

        if (dnsMessage == null || dnsMessage.isTruncated()) {
            dnsMessage = queryTcp(address, port, message);
        }

        if (dnsMessage == null) {
            return null;
        }

        for (Record record : dnsMessage.getAnswers()) {
            if (record.isAnswer(q)) {
                if (cache != null) {
                    cache.put(q, dnsMessage);
                }
                break;
            }
        }
        return dnsMessage;
    }
}
