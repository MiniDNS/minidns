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

import de.measite.minidns.DNSSECConstants.DigestAlgorithm;
import de.measite.minidns.DNSSECConstants.SignatureAlgorithm;
import de.measite.minidns.Record.CLASS;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.DLV;
import de.measite.minidns.record.DNSKEY;
import de.measite.minidns.record.DS;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.MX;
import de.measite.minidns.record.NS;
import de.measite.minidns.record.NSEC;
import de.measite.minidns.record.NSEC3;
import de.measite.minidns.record.RRSIG;
import de.measite.minidns.record.SOA;
import de.measite.minidns.record.SRV;
import de.measite.minidns.source.DNSDataSource;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class DNSWorld extends DNSDataSource {
    private List<PreparedResponse> answers = new ArrayList<>();

    @Override
    public DNSMessage query(DNSMessage message, InetAddress address, int port) {
        assertNotNull(message);
        assertNotNull(address);
        assertEquals(53, port);

        for (PreparedResponse answer : answers) {
            if (answer.isResponse(message, address)) {
                DNSMessage.Builder response = answer.getResponse().asBuilder();
                response.setId(message.id);
                response.setQuestions(message.questions);
                return response.build();
            }
        }
        // TODO We should return an error or throw an IOException here. Otherwise the (DNSSEC) unit tests will log a
        // bunch of server "NULL response from..." messages.
        return null;
    }

    public void addPreparedResponse(PreparedResponse answer) {
        answers.add(answer);
    }

    public interface PreparedResponse {
        boolean isResponse(DNSMessage request, InetAddress address);

        DNSMessage getResponse();
    }

    public static class AnswerResponse implements PreparedResponse {
        final DNSMessage request;
        final DNSMessage response;

        public AnswerResponse(DNSMessage request, DNSMessage response) {
            this.request = request;
            this.response = response;
        }

        @Override
        public boolean isResponse(DNSMessage request, InetAddress address) {
            List<Question> questions = this.request.copyQuestions();
            for (Question q : request.questions) {
                if (!hasQuestion(questions, q)) {
                    return false;
                }
            }
            return questions.isEmpty();
        }

        @Override
        public DNSMessage getResponse() {
            return response;
        }

        private static boolean hasQuestion(Collection<Question> questions, Question q) {
            for (Iterator<Question> iterator = questions.iterator(); iterator.hasNext(); ) {
                if (iterator.next().equals(q)) {
                    iterator.remove();
                    return true;
                }
            }
            return false;
        }

        @Override
        public String toString() {
            return
                    "req: " + request + '\n'
                  + "res: " + response + '\n';
        }
    }

    public static class RootAnswerResponse extends AnswerResponse {

        public RootAnswerResponse(DNSMessage request, DNSMessage response) {
            super(request, response);
        }

        @Override
        public boolean isResponse(DNSMessage request, InetAddress address) {
            return address.getHostName().endsWith(".root-servers.net") && super.isResponse(request, address);
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + '\n' + super.toString();
        }
    }

    public static class AddressedAnswerResponse extends AnswerResponse {

        final InetAddress address;

        public AddressedAnswerResponse(InetAddress address, DNSMessage request, DNSMessage response) {
            super(request, response);
            this.address = address;
        }

        @Override
        public boolean isResponse(DNSMessage request, InetAddress address) {
            return address.equals(this.address) && super.isResponse(request, address);
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + ": " + address + '\n' + super.toString();
        }
    }

    public abstract static class HintsResponse implements PreparedResponse {
        final DNSName ending;
        final DNSMessage response;

        public HintsResponse(DNSName ending, DNSMessage response) {
            this.ending = ending;
            this.response = response;
        }

        boolean questionHintable(DNSMessage request) {
            for (Question question : request.questions) {
                if (question.name.isChildOf(ending) || question.name.equals(ending)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public DNSMessage getResponse() {
            return response;
        }

        @Override
        public String toString() {
            return
                    getClass().getSimpleName() + ": " + ending + '\n'
                  + response;
        }
    }

    public static class RootHintsResponse extends HintsResponse {

        public RootHintsResponse(DNSName ending, DNSMessage response) {
            super(ending, response);
        }

        @Override
        public boolean isResponse(DNSMessage request, InetAddress address) {
            return address.getHostName().endsWith(".root-servers.net") && questionHintable(request);
        }
    }

    public static class AddressedHintsResponse extends HintsResponse {
        final InetAddress address;

        public AddressedHintsResponse(InetAddress address, DNSName ending, DNSMessage response) {
            super(ending, response);
            this.address = address;
        }

        @Override
        public boolean isResponse(DNSMessage request, InetAddress address) {
            return address.equals(this.address) && questionHintable(request);
        }

        @Override
        public String toString() {
            return
                    getClass().getSimpleName() + ": " + address + '\n'
                  + response;
        }
    }

    public static class Zone {
        String zoneName;
        InetAddress address;
        List<Record<? extends Data>> records;

        public Zone(String zoneName, InetAddress address, List<Record<? extends Data>> records) {
            this.zoneName = zoneName;
            this.address = address;
            this.records = records;
        }

        public List<RRSet> getRRSets() {
            List<RRSet.Builder> rrSetBuilders = new LinkedList<>();
            outerloop: for (Record<? extends Data> record : records) {
                for (RRSet.Builder builder : rrSetBuilders) {
                    if (builder.addIfPossible(record)) {
                        continue outerloop;
                    }
                }
                rrSetBuilders.add(RRSet.builder().addRecord(record));
            }
            List<RRSet> rrSets = new ArrayList<>(rrSetBuilders.size());
            for (RRSet.Builder builder : rrSetBuilders) {
                rrSets.add(builder.build());
            }
            return rrSets;
        }

        boolean isRootZone() {
            return (zoneName == null || zoneName.isEmpty()) && address == null;
        }
    }

    public static DNSWorld applyZones(AbstractDNSClient client, Zone... zones) {
        DNSWorld world = new DNSWorld();
        client.setDataSource(world);
        for (Zone zone : zones) {
            for (RRSet rrSet : zone.getRRSets()) {
                DNSMessage.Builder req = client.buildMessage(new Question(rrSet.name, rrSet.type, rrSet.clazz, false));
                DNSMessage.Builder resp = DNSMessage.builder();
                resp.setAnswers(rrSet.records);
                resp.setAuthoritativeAnswer(true);
                attachGlues(resp, rrSet.records, zone.records);
                attachSignatures(resp, zone.records);
                DNSMessage request = req.build();
                DNSMessage response = resp.build();
                if (zone.isRootZone()) {
                    world.addPreparedResponse(new RootAnswerResponse(request, response));
                } else {
                    world.addPreparedResponse(new AddressedAnswerResponse(zone.address, request, response));
                }
                if (rrSet.type == TYPE.NS) {
                    DNSMessage.Builder hintsResp = DNSMessage.builder();
                    hintsResp.setNameserverRecords(rrSet.records);
                    hintsResp.setAdditionalResourceRecords(response.additionalSection);
                    DNSMessage hintsResponse = hintsResp.build();
                    if (zone.isRootZone()) {
                        world.addPreparedResponse(new RootHintsResponse(rrSet.name, hintsResponse));
                    } else {
                        world.addPreparedResponse(new AddressedHintsResponse(zone.address, rrSet.name, hintsResponse));
                    }
                }
            }
        }
        return world;
    }

    static void attachSignatures(DNSMessage.Builder response, List<Record<? extends Data>> records) {
        List<Record<? extends Data>> recordList = new ArrayList<>(records.size());
        for (Record<? extends Data> record : response.getAnswers()) {
            for (Record<? extends Data> r : records) {
                if (r.name.equals(record.name) && r.type == TYPE.RRSIG && ((RRSIG) r.payloadData).typeCovered == record.type) {
                    recordList.add(r);
                }
            }
        }
        response.addAnswers(recordList);

        recordList.clear();

        for (Record<? extends Data> record : response.getAdditionalResourceRecords()) {
            for (Record<? extends Data> r : records) {
                if (r.name.equals(record.name) && r.type == TYPE.RRSIG && ((RRSIG) r.payloadData).typeCovered == record.type) {
                    recordList.add(r);
                }
            }
        }
        response.addAdditionalResourceRecords(recordList);
    }

    static void attachGlues(DNSMessage.Builder response, Collection<Record<? extends Data>> answers, List<Record<? extends Data>> records) {
        List<Record<? extends Data>> glues = new ArrayList<>();
        for (Record<? extends Data> record : answers) {
            if (record.type == TYPE.CNAME) {
                glues.addAll(findGlues(((CNAME) record.payloadData).name, records));
            } else if (record.type == TYPE.NS) {
                glues.addAll(findGlues(((NS) record.payloadData).name, records));
            } else if (record.type == TYPE.SRV) {
                glues.addAll(findGlues(((SRV) record.payloadData).name, records));
            }
        }

        if (!glues.isEmpty()) {
            response.setAdditionalResourceRecords(glues);
        }
    }

    private static List<Record<? extends Data>> findGlues(DNSName name, List<Record<? extends Data>> records) {
        List<Record<? extends Data>> glues = new ArrayList<>();
        for (Record<? extends Data> record : records) {
            if (record.name.equals(name)) {
                if (record.type == TYPE.CNAME) {
                    glues.addAll(findGlues(((CNAME) record.payloadData).name, records));
                } else if (record.type == TYPE.A || record.type == TYPE.AAAA) {
                    glues.add(record);
                }
            }
        }
        return glues;
    }

    @SuppressWarnings("unchecked")
    public static DNSWorld applyStubRecords(AbstractDNSClient client, Record<Data>... records) {
        DNSWorld world = new DNSWorld();
        client.setDataSource(world);
        for (Record<? extends Data> record : records) {
            DNSMessage.Builder request = client.buildMessage(new Question(record.name, record.type, record.clazz, record.unicastQuery));
            request.setRecursionDesired(true);
            DNSMessage.Builder response = DNSMessage.builder();
            response.addAnswer(record);
            response.setRecursionAvailable(true);
            world.addPreparedResponse(new AnswerResponse(request.build(), response.build()));
        }
        return world;
    }

    @SuppressWarnings("unchecked")
    public static Zone rootZone(Record<? extends Data>... records) {
        List<Record<? extends Data>> listOfRecords = new ArrayList<>(records.length);
        for (Record<? extends Data> record : records) {
            listOfRecords.add(record);
        }
        return rootZone(listOfRecords);
    }

    public static Zone rootZone(List<Record<? extends Data>> records) {
        return new Zone("", null, records);
    }

    @SuppressWarnings("unchecked")
    public static Zone zone(String zoneName, String nsName, String nsIp, Record<? extends Data>... records) {
        List<Record<? extends Data>> listOfRecords = new ArrayList<>(records.length);
        for (Record<? extends Data> record : records) {
            listOfRecords.add(record);
        }
        return zone(zoneName, nsName, nsIp, listOfRecords);
    }

    public static Zone zone(String zoneName, String nsName, String nsIp, List<Record<? extends Data>> records) {
        try {
            return zone(zoneName, InetAddress.getByAddress(nsName, parseIpV4(nsIp)), records);
        } catch (UnknownHostException e) {
            // This will never happen, as we already ensured the validity of the IP address by using parseIpV4()
            throw new RuntimeException(e);
        }
    }

    public static Zone zone(String zoneName, InetAddress address, List<Record<? extends Data>> records) {
        return new Zone(zoneName, address, records);
    }

    public static Record<Data> record(String name, long ttl, Data data) {
        return new Record<>(name, data.getType(), CLASS.IN, ttl, data, false);
    }

    public static Record<Data> record(DNSName name, long ttl, Data data) {
        return new Record<>(name, data.getType(), CLASS.IN, ttl, data, false);
    }

    public static Record<Data> record(String name, Data data) {
        return record(name, 3600, data);
    }

    public static A a(byte[] ip) {
        return new A(ip);
    }

    public static A a(String ipString) {
        return a(parseIpV4(ipString));
    }

    public static AAAA aaaa(byte[] ip) {
        return new AAAA(ip);
    }

    public static AAAA aaaa(String ipString) {
        return aaaa(parseIpV6(ipString));
    }

    public static CNAME cname(String name) {
        return cname(DNSName.from(name));
    }

    public static CNAME cname(DNSName name) {
        return new CNAME(name);
    }

    public static DNSKEY dnskey(int flags, int protocol, SignatureAlgorithm algorithm, byte[] key) {
        return new DNSKEY((short) flags, (byte) protocol, algorithm, key);
    }

    public static DNSKEY dnskey(int flags, SignatureAlgorithm algorithm, byte[] key) {
        return dnskey(flags, DNSKEY.PROTOCOL_RFC4034, algorithm, key);
    }

    public static DS ds(int keyTag, SignatureAlgorithm algorithm, DigestAlgorithm digestType, byte[] digest) {
        return new DS(keyTag, algorithm, digestType, digest);
    }

    public static DS ds(int keyTag, SignatureAlgorithm algorithm, byte digestType, byte[] digest) {
        return new DS(keyTag, algorithm, digestType, digest);
    }

    public static DLV dlv(int keyTag, SignatureAlgorithm algorithm, DigestAlgorithm digestType, byte[] digest) {
        return new DLV(keyTag, algorithm, digestType, digest);
    }

    public static MX mx(int priority, String name) {
        return mx(priority, DNSName.from(name));
    }

    public static MX mx(int priority, DNSName name) {
        return new MX(priority, name);
    }

    public static MX mx(String name) {
        return mx(10, name);
    }

    public static NS ns(String name) {
        return ns(DNSName.from(name));
    }

    public static NS ns(DNSName name) {
        return new NS(name);
    }

    public static NSEC nsec(String next, TYPE... types) {
        return nsec(DNSName.from(next), types);
    }

    public static NSEC nsec(DNSName next, TYPE... types) {
        return new NSEC(next, types);
    }

    public static NSEC3 nsec3(byte hashAlgorithm, byte flags, int iterations, byte[] salt, byte[] nextHashed, TYPE... types) {
        return new NSEC3(hashAlgorithm, flags, iterations, salt, nextHashed, types);
    }

    public static RRSIG rrsig(TYPE typeCovered, SignatureAlgorithm algorithm, int labels, long originalTtl, Date signatureExpiration,
                              Date signatureInception, int keyTag, String signerName, byte[] signature) {
        return rrsig(typeCovered, algorithm, (byte) labels, originalTtl, signatureExpiration,
                signatureInception, keyTag, DNSName.from(signerName), signature);
    }

    public static RRSIG rrsig(TYPE typeCovered, SignatureAlgorithm algorithm, int labels, long originalTtl,
            Date signatureExpiration, Date signatureInception, int keyTag, DNSName signerName, byte[] signature) {
        return new RRSIG(typeCovered, algorithm, (byte) labels, originalTtl, signatureExpiration, signatureInception,
                keyTag, signerName, signature);
    }

    public static RRSIG rrsig(TYPE typeCovered, int algorithm,
            int labels, long originalTtl, Date signatureExpiration,
            Date signatureInception, int keyTag, String signerName,
            byte[] signature) {
        return rrsig(typeCovered, algorithm, (byte) labels,
                originalTtl, signatureExpiration, signatureInception, keyTag,
                DNSName.from(signerName), signature);
    }

    public static RRSIG rrsig(TYPE typeCovered, int algorithm,
            int labels, long originalTtl, Date signatureExpiration,
            Date signatureInception, int keyTag, DNSName signerName,
            byte[] signature) {
        return new RRSIG(typeCovered, algorithm, (byte) labels,
                originalTtl, signatureExpiration, signatureInception, keyTag,
                signerName, signature);
    }

    public static SOA soa(String mname, String rname, long serial, int refresh, int retry, int expire, long minimum) {
        return soa(DNSName.from(mname), DNSName.from(rname), serial, refresh, retry, expire, minimum);
    }

    public static SOA soa(DNSName mname, DNSName rname, long serial, int refresh, int retry, int expire, long minimum) {
        return new SOA(mname, rname, serial, refresh, retry, expire, minimum);
    }

    public static SRV srv(int priority, int weight, int port, String name) {
        return srv(priority, weight, port, DNSName.from(name));
    }

    public static SRV srv(int priority, int weight, int port, DNSName name) {
        return new SRV(priority, weight, port, name);
    }

    public static SRV srv(int port, String name) {
        return srv(10, 10, port, name);
    }

    public static byte[] parseIpV4(String ipString) {
        String[] split = ipString.split("\\.");
        if (split.length != 4) {
            throw new IllegalArgumentException(ipString + " is not an valid IPv4 address");
        }
        byte[] ip = new byte[4];
        for (int i = 0; i < 4; i++) {
            ip[i] = (byte) Integer.parseInt(split[i]);
        }
        return ip;
    }

    static byte[] parseIpV6(String ipString) {
        try {
            return InetAddress.getByName(ipString).getAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(ipString + " is not an valid IPv6 address", e);
        }
    }
}
