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
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.record.A;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.NS;
import de.measite.minidns.record.SRV;
import de.measite.minidns.source.DNSDataSource;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
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
                DNSMessage response = answer.getResponse();
                response.id = message.id;
                return response;
            }
        }
        return null;
    }

    public void addPreparedResponse(PreparedResponse answer) {
        answers.add(answer);
    }

    private static DNSMessage createEmptyResponseMessage() {
        DNSMessage message = new DNSMessage();
        message.answers = new Record[0];
        message.nameserverRecords = new Record[0];
        message.questions = new Question[0];
        message.additionalResourceRecords = new Record[0];
        message.responseCode = RESPONSE_CODE.NO_ERROR;
        message.opcode = OPCODE.QUERY;
        return message;
    }

    interface PreparedResponse {
        boolean isResponse(DNSMessage request, InetAddress address);

        DNSMessage getResponse();
    }

    static class AnswerResponse implements PreparedResponse {
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

    static class RootAnswerResponse extends AnswerResponse {

        public RootAnswerResponse(DNSMessage request, DNSMessage response) {
            super(request, response);
        }

        @Override
        public boolean isResponse(DNSMessage request, InetAddress address) {
            return address.getHostName().endsWith(".root-servers.net") && super.isResponse(request, address);
        }
    }

    static class AddressedAnswerResponse extends AnswerResponse {

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

    abstract static class HintsResponse implements PreparedResponse {
        final String ending;
        final DNSMessage response;

        public HintsResponse(String ending, DNSMessage response) {
            this.ending = ending;
            this.response = response;
        }

        boolean questionHintable(DNSMessage request) {
            for (Question question : request.questions) {
                if (question.name.endsWith("." + ending)) {
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

    static class RootHintsResponse extends HintsResponse {

        public RootHintsResponse(String ending, DNSMessage response) {
            super(ending, response);
        }

        @Override
        public boolean isResponse(DNSMessage request, InetAddress address) {
            return address.getHostName().endsWith(".root-servers.net") && questionHintable(request);
        }
    }

    static class AddressedHintsResponse extends HintsResponse {
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

        boolean isRootZone() {
            return (zoneName == null || zoneName.isEmpty()) && address == null;
        }
    }

    public static DNSWorld applyZones(AbstractDNSClient client, Zone... zones) {
        DNSWorld world = new DNSWorld();
        client.setDataSource(world);
        for (Zone zone : zones) {
            for (Record record : zone.records) {
                DNSMessage request = client.buildMessage(new Question(record.name, record.type, record.clazz, record.unicastQuery));
                DNSMessage response = createEmptyResponseMessage();
                response.answers = new Record[]{record};
                response.authoritativeAnswer = true;
                attachGlues(response, record, zone.records);
                if (zone.isRootZone()) {
                    world.addPreparedResponse(new RootAnswerResponse(request, response));
                } else {
                    world.addPreparedResponse(new AddressedAnswerResponse(zone.address, request, response));
                }
                if (record.type == TYPE.NS) {
                    DNSMessage hintsResponse = createEmptyResponseMessage();
                    hintsResponse.nameserverRecords = new Record[]{record};
                    hintsResponse.additionalResourceRecords = response.additionalResourceRecords;
                    if (zone.isRootZone()) {
                        world.addPreparedResponse(new RootHintsResponse(record.name, hintsResponse));
                    } else {
                        world.addPreparedResponse(new AddressedHintsResponse(zone.address, record.name, hintsResponse));
                    }
                }
            }
        }
        return world;
    }

    static void attachGlues(DNSMessage response, Record record, Record[] records) {
        List<Record> glues = null;
        if (record.type == TYPE.CNAME) {
            glues = findGlues(((CNAME) record.payloadData).name, records);
        } else if (record.type == TYPE.NS) {
            glues = findGlues(((NS) record.payloadData).name, records);
        } else if (record.type == TYPE.SRV) {
            glues = findGlues(((SRV) record.payloadData).name, records);
        }

        if (glues != null) {
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
            return zone(zoneName, InetAddress.getByAddress(nsName, parseIp(nsIp)), records);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    public static Zone zone(String zoneName, InetAddress address, Record... records) {
        return new Zone(zoneName, address, records);
    }

    public static Record record(String name, long ttl, Data data) {
        return new Record(name, data.getType(), Record.CLASS.IN, ttl, data, false);
    }

    public static Record record(String name, Data data) {
        return record(name, 3600, data);
    }

    public static A a(byte[] ip) {
        return new A(ip);
    }

    public static A a(String ipString) {
        byte[] ip = parseIp(ipString);
        return a(ip);
    }

    static byte[] parseIp(String ipString) {
        String[] split = ipString.split("\\.");
        byte[] ip = new byte[4];
        for (int i = 0; i < 4; i++) {
            ip[i] = (byte) Integer.parseInt(split[i]);
        }
        return ip;
    }

    public static CNAME cname(String name) {
        return new CNAME(name);
    }

    public static NS ns(String name) {
        return new NS(name);
    }
}
