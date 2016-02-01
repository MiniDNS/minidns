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

import de.measite.minidns.DNSMessage.OPCODE;
import de.measite.minidns.DNSMessage.RESPONSE_CODE;
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

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

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
                DNSMessage response = answer.getResponse();
                response.id = message.id;
                response.questions = message.questions.clone();
                return response;
            }
        }
        return null;
    }

    public void addPreparedResponse(PreparedResponse answer) {
        answers.add(answer);
    }

    public static DNSMessage createEmptyResponseMessage() {
        DNSMessage message = new DNSMessage();
        message.answers = new Record[0];
        message.nameserverRecords = new Record[0];
        message.questions = new Question[0];
        message.additionalResourceRecords = new Record[0];
        message.responseCode = RESPONSE_CODE.NO_ERROR;
        message.opcode = OPCODE.QUERY;
        return message;
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
            ArrayList<Question> questions = new ArrayList<>(Arrays.asList(this.request.questions));
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

        private static boolean hasQuestion(ArrayList<Question> questions, Question q) {
            for (Iterator<Question> iterator = questions.iterator(); iterator.hasNext(); ) {
                if (iterator.next().equals(q)) {
                    iterator.remove();
                    return true;
                }
            }
            return false;
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
    }

    public abstract static class HintsResponse implements PreparedResponse {
        final String ending;
        final DNSMessage response;

        public HintsResponse(String ending, DNSMessage response) {
            this.ending = ending;
            this.response = response;
        }

        boolean questionHintable(DNSMessage request) {
            for (Question question : request.questions) {
                if (question.name.endsWith("." + ending) || question.name.equals(ending)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public DNSMessage getResponse() {
            return response;
        }
    }

    public static class RootHintsResponse extends HintsResponse {

        public RootHintsResponse(String ending, DNSMessage response) {
            super(ending, response);
        }

        @Override
        public boolean isResponse(DNSMessage request, InetAddress address) {
            return address.getHostName().endsWith(".root-servers.net") && questionHintable(request);
        }
    }

    public static class AddressedHintsResponse extends HintsResponse {
        final InetAddress address;

        public AddressedHintsResponse(InetAddress address, String ending, DNSMessage response) {
            super(ending, response);
            this.address = address;
        }

        @Override
        public boolean isResponse(DNSMessage request, InetAddress address) {
            return address.equals(this.address) && questionHintable(request);
        }
    }

    public static class Zone {
        String zoneName;
        InetAddress address;
        Record[] records;

        public Zone(String zoneName, InetAddress address, Record[] records) {
            this.zoneName = zoneName;
            this.address = address;
            this.records = records;
        }

        public List<RRSet> getRRSets() {
            List<RRSet> rrSets = new ArrayList<>();
            for (Record record : records) {
                boolean add = true;
                for (RRSet rrSet : rrSets) {
                    if (rrSet.name.equals(record.name) && rrSet.type == record.type) {
                        rrSet.records.add(record);
                        add = false;
                    }
                }
                if (add) rrSets.add(new RRSet(record));
            }
            return rrSets;
        }

        boolean isRootZone() {
            return (zoneName == null || zoneName.isEmpty()) && address == null;
        }
    }

    private static class RRSet {
        String name;
        TYPE type;
        CLASS clazz;
        Set<Record> records = new HashSet<>();

        public RRSet(Record record) {
            name = record.name;
            type = record.type;
            clazz = record.clazz;

            records.add(record);
        }
    }

    public static DNSWorld applyZones(AbstractDNSClient client, Zone... zones) {
        DNSWorld world = new DNSWorld();
        client.setDataSource(world);
        for (Zone zone : zones) {
            for (RRSet rrSet : zone.getRRSets()) {
                DNSMessage request = client.buildMessage(new Question(rrSet.name, rrSet.type, rrSet.clazz, false));
                DNSMessage response = createEmptyResponseMessage();
                response.answers = rrSet.records.toArray(new Record[rrSet.records.size()]);
                response.authoritativeAnswer = true;
                attachGlues(response, response.answers, zone.records);
                attachSignatures(response, zone.records);
                if (zone.isRootZone()) {
                    world.addPreparedResponse(new RootAnswerResponse(request, response));
                } else {
                    world.addPreparedResponse(new AddressedAnswerResponse(zone.address, request, response));
                }
                if (rrSet.type == TYPE.NS) {
                    DNSMessage hintsResponse = createEmptyResponseMessage();
                    hintsResponse.nameserverRecords = rrSet.records.toArray(new Record[rrSet.records.size()]);
                    hintsResponse.additionalResourceRecords = response.additionalResourceRecords;
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

    static void attachSignatures(DNSMessage response, Record[] records) {
        List<Record> recordList = new ArrayList<>();
        for (Record record : response.answers) {
            for (Record r : records) {
                if (r.name.equals(record.name) && r.type == TYPE.RRSIG && ((RRSIG) r.payloadData).typeCovered == record.type) {
                    recordList.add(r);
                }
            }
        }
        if (!recordList.isEmpty()) {
            recordList.addAll(Arrays.asList(response.answers));
            response.answers = recordList.toArray(new Record[recordList.size()]);
        }

        recordList = new ArrayList<>();
        for (Record record : response.additionalResourceRecords) {
            for (Record r : records) {
                if (r.name.equals(record.name) && r.type == TYPE.RRSIG && ((RRSIG) r.payloadData).typeCovered == record.type) {
                    recordList.add(r);
                }
            }
        }
        if (!recordList.isEmpty()) {
            recordList.addAll(Arrays.asList(response.additionalResourceRecords));
            response.additionalResourceRecords = recordList.toArray(new Record[recordList.size()]);
        }
    }

    static void attachGlues(DNSMessage response, Record[] answers, Record[] records) {
        List<Record> glues = new ArrayList<>();
        for (Record record : answers) {
            if (record.type == TYPE.CNAME) {
                glues.addAll(findGlues(((CNAME) record.payloadData).name, records));
            } else if (record.type == TYPE.NS) {
                glues.addAll(findGlues(((NS) record.payloadData).name, records));
            } else if (record.type == TYPE.SRV) {
                glues.addAll(findGlues(((SRV) record.payloadData).name, records));
            }
        }

        if (!glues.isEmpty()) {
            response.additionalResourceRecords = glues.toArray(new Record[glues.size()]);
        }
    }

    private static List<Record> findGlues(String name, Record[] records) {
        List<Record> glues = new ArrayList<>();
        for (Record record : records) {
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

    public static DNSWorld applyStubRecords(AbstractDNSClient client, Record... records) {
        DNSWorld world = new DNSWorld();
        client.setDataSource(world);
        for (Record record : records) {
            DNSMessage request = client.buildMessage(new Question(record.name, record.type, record.clazz, record.unicastQuery));
            request.recursionDesired = true;
            DNSMessage response = createEmptyResponseMessage();
            response.answers = new Record[]{record};
            response.recursionAvailable = true;
            world.addPreparedResponse(new AnswerResponse(request, response));
        }
        return world;
    }

    public static Zone rootZone(Record... records) {
        return new Zone("", null, records);
    }

    public static Zone zone(String zoneName, String nsName, String nsIp, Record... records) {
        try {
            return zone(zoneName, InetAddress.getByAddress(nsName, parseIpV4(nsIp)), records);
        } catch (UnknownHostException e) {
            // This will never happen, as we already ensured the validity of the IP address by using parseIpV4()
            throw new RuntimeException(e);
        }
    }

    public static Zone zone(String zoneName, InetAddress address, Record... records) {
        return new Zone(zoneName, address, records);
    }

    public static Record record(String name, long ttl, Data data) {
        return new Record(name, data.getType(), CLASS.IN, ttl, data, false);
    }

    public static Record record(String name, Data data) {
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
        return new CNAME(name);
    }

    public static DNSKEY dnskey(int flags, int protocol, byte algorithm, byte[] key) {
        return new DNSKEY((short) flags, (byte) protocol, algorithm, key);
    }

    public static DNSKEY dnskey(int flags, byte algorithm, byte[] key) {
        return dnskey(flags, DNSKEY.PROTOCOL_RFC4034, algorithm, key);
    }

    public static DS ds(int keyTag, byte algorithm, byte digestType, byte[] digest) {
        return new DS(keyTag, algorithm, digestType, digest);
    }

    public static DLV dlv(int keyTag, byte algorithm, byte digestType, byte[] digest) {
        return new DLV(keyTag, algorithm, digestType, digest);
    }

    public static MX mx(int priority, String name) {
        return new MX(priority, name);
    }

    public static MX mx(String name) {
        return mx(10, name);
    }

    public static NS ns(String name) {
        return new NS(name);
    }

    public static NSEC nsec(String next, TYPE... types) {
        return new NSEC(next, types);
    }

    public static NSEC3 nsec3(byte hashAlgorithm, byte flags, int iterations, byte[] salt, byte[] nextHashed, TYPE... types) {
        return new NSEC3(hashAlgorithm, flags, iterations, salt, nextHashed, types);
    }

    public static RRSIG rrsig(TYPE typeCovered, int algorithm, int labels, long originalTtl, Date signatureExpiration,
                              Date signatureInception, int keyTag, String signerName, byte[] signature) {
        return new RRSIG(typeCovered, (byte) algorithm, (byte) labels, originalTtl, signatureExpiration,
                signatureInception, keyTag, signerName, signature);
    }

    public static SOA soa(String mname, String rname, long serial, int refresh, int retry, int expire, long minimum) {
        return new SOA(mname, rname, serial, refresh, retry, expire, minimum);
    }

    public static SRV srv(int priority, int weight, int port, String name) {
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
            return Inet6Address.getByName(ipString).getAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(ipString + " is not an valid IPv6 address", e);
        }
    }
}
