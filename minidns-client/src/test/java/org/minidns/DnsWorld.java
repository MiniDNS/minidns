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
package org.minidns;

import org.minidns.constants.DnsRootServer;
import org.minidns.constants.DnssecConstants.DigestAlgorithm;
import org.minidns.constants.DnssecConstants.SignatureAlgorithm;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.DnsMessage.RESPONSE_CODE;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsname.DnsName;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.dnsqueryresult.TestWorldDnsQueryResult;
import org.minidns.record.A;
import org.minidns.record.AAAA;
import org.minidns.record.CNAME;
import org.minidns.record.DLV;
import org.minidns.record.DNSKEY;
import org.minidns.record.DS;
import org.minidns.record.Data;
import org.minidns.record.MX;
import org.minidns.record.NS;
import org.minidns.record.NSEC;
import org.minidns.record.NSEC3;
import org.minidns.record.RRSIG;
import org.minidns.record.Record;
import org.minidns.record.SOA;
import org.minidns.record.SRV;
import org.minidns.record.Record.CLASS;
import org.minidns.record.Record.TYPE;
import org.minidns.source.AbstractDnsDataSource;
import org.minidns.util.InetAddressUtil;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class DnsWorld extends AbstractDnsDataSource {
    private List<PreparedResponse> answers = new ArrayList<>();

    private final Map<DnsName, Map<TYPE, RrSet>> worldData = new HashMap<>();

    @Override
    public DnsQueryResult query(DnsMessage message, InetAddress address, int port) {
        assertNotNull(message);
        assertNotNull(address);
        assertEquals(53, port);

        for (PreparedResponse answer : answers) {
            if (answer.isResponse(message, address)) {
                DnsMessage.Builder response = answer.getResponse().asBuilder();
                response.setId(message.id);
                response.setQuestions(message.questions);
                return new TestWorldDnsQueryResult(message, response.build(), answer);
            }
        }

        DnsMessage nxDomainResponse = message
                .getResponseBuilder(RESPONSE_CODE.NX_DOMAIN)
                // TODO: This RA is faked and eventually causes problems.
                .setRecursionAvailable(true)
                .setAuthoritativeAnswer(true)
                .build();
        return new TestWorldDnsQueryResult(message, nxDomainResponse);
    }

    public void addPreparedResponse(PreparedResponse answer) {
        answers.add(answer);
    }

    public interface PreparedResponse {
        boolean isResponse(DnsMessage request, InetAddress address);

        DnsMessage getResponse();
    }

    public static class AnswerResponse implements PreparedResponse {
        final DnsMessage request;
        final DnsMessage response;

        public AnswerResponse(DnsMessage request, DnsMessage response) {
            this.request = request;
            this.response = response;
        }

        @Override
        public boolean isResponse(DnsMessage request, InetAddress address) {
            List<Question> questions = this.request.copyQuestions();
            for (Question q : request.questions) {
                if (!hasQuestion(questions, q)) {
                    return false;
                }
            }
            return questions.isEmpty();
        }

        @Override
        public DnsMessage getResponse() {
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

        public RootAnswerResponse(DnsMessage request, DnsMessage response) {
            super(request, response);
        }

        @Override
        public boolean isResponse(DnsMessage request, InetAddress address) {
            return address.getHostName().endsWith(".root-servers.net") && super.isResponse(request, address);
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + '\n' + super.toString();
        }
    }

    public static class AddressedAnswerResponse extends AnswerResponse {

        final InetAddress address;

        public AddressedAnswerResponse(InetAddress address, DnsMessage request, DnsMessage response) {
            super(request, response);
            this.address = address;
        }

        @Override
        public boolean isResponse(DnsMessage request, InetAddress address) {
            return address.equals(this.address) && super.isResponse(request, address);
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + ": " + address + '\n' + super.toString();
        }
    }

    public abstract static class HintsResponse implements PreparedResponse {
        final DnsName ending;
        final DnsMessage response;

        public HintsResponse(DnsName ending, DnsMessage response) {
            this.ending = ending;
            this.response = response;
        }

        boolean questionHintable(DnsMessage request) {
            for (Question question : request.questions) {
                if (question.name.isChildOf(ending) || question.name.equals(ending)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public DnsMessage getResponse() {
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

        public RootHintsResponse(DnsName ending, DnsMessage response) {
            super(ending, response);
        }

        @Override
        public boolean isResponse(DnsMessage request, InetAddress address) {
            // TODO: It appears that we shouldn't hint down to the nameserver if the query is about a 'DS' RR. Because
            // they have to get answered at the parental part of the zone cut.
            if (request.getQuestion().type == TYPE.DS) {
                return false;
            }
            return address.getHostName().endsWith(".root-servers.net") && questionHintable(request);
        }
    }

    public static class AddressedHintsResponse extends HintsResponse {
        final InetAddress address;

        public AddressedHintsResponse(InetAddress address, DnsName ending, DnsMessage response) {
            super(ending, response);
            this.address = address;
        }

        @Override
        public boolean isResponse(DnsMessage request, InetAddress address) {
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
        // TODO: Change type of zoneName to DnsName and make fields final.
        String zoneName;
        InetAddress address;
        List<Record<? extends Data>> records;

        public Zone(String zoneName, InetAddress address, List<Record<? extends Data>> records) {
            this.zoneName = zoneName;
            this.address = address;
            this.records = records;
        }

        public List<RrSet> getRRSets() {
            List<RrSet.Builder> rrSetBuilders = new LinkedList<>();
            outerloop: for (Record<? extends Data> record : records) {
                for (RrSet.Builder builder : rrSetBuilders) {
                    if (builder.addIfPossible(record)) {
                        continue outerloop;
                    }
                }
                rrSetBuilders.add(RrSet.builder().addRecord(record));
            }
            List<RrSet> rrSets = new ArrayList<>(rrSetBuilders.size());
            for (RrSet.Builder builder : rrSetBuilders) {
                rrSets.add(builder.build());
            }
            return rrSets;
        }

        boolean isRootZone() {
            return (zoneName == null || zoneName.isEmpty()) && address == null;
        }
    }

    public static DnsWorld applyZones(AbstractDnsClient client, Zone... zones) {
        DnsWorld world = new DnsWorld();
        client.setDataSource(world);
        for (Zone zone : zones) {
            for (RrSet rrSet : zone.getRRSets()) {
                // A zone may have glue RR sets, so we need use rrSet.name as zoneName here.
                DnsName zoneName = rrSet.name;
                Map<TYPE, RrSet> zoneData = world.worldData.get(zoneName);
                if (zoneData == null) {
                    zoneData = new HashMap<>();
                    world.worldData.put(zoneName, zoneData);
                }

                // TODO: Shouldn't we try to merge with a previously existing rrSet of the same type instead of
                // overriding it? Or does this not happen by construction?
                zoneData.put(rrSet.type, rrSet);

                DnsMessage.Builder req = client.buildMessage(new Question(rrSet.name, rrSet.type, rrSet.clazz, false));
                DnsMessage.Builder resp = DnsMessage.builder();
                resp.setAnswers(rrSet.records);
                resp.setAuthoritativeAnswer(true);
                attachGlues(resp, rrSet.records, zone.records);
                attachSignatures(resp, zone.records);
                DnsMessage request = req.build();
                DnsMessage response = resp.build();
                if (zone.isRootZone()) {
                    world.addPreparedResponse(new RootAnswerResponse(request, response));
                } else {
                    world.addPreparedResponse(new AddressedAnswerResponse(zone.address, request, response));
                }
                if (rrSet.type == TYPE.NS) {
                    DnsMessage.Builder hintsResp = DnsMessage.builder();
                    hintsResp.setNameserverRecords(rrSet.records);
                    hintsResp.setAdditionalResourceRecords(response.additionalSection);
                    DnsMessage hintsResponse = hintsResp.build();
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

    static void attachSignatures(DnsMessage.Builder response, List<Record<? extends Data>> records) {
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

    static void attachGlues(DnsMessage.Builder response, Collection<Record<? extends Data>> answers, List<Record<? extends Data>> records) {
        List<Record<? extends Data>> glues = new ArrayList<>();
        for (Record<? extends Data> record : answers) {
            if (record.type == TYPE.CNAME) {
                glues.addAll(findGlues(((CNAME) record.payloadData).target, records));
            } else if (record.type == TYPE.NS) {
                glues.addAll(findGlues(((NS) record.payloadData).target, records));
            } else if (record.type == TYPE.SRV) {
                glues.addAll(findGlues(((SRV) record.payloadData).target, records));
            }
        }

        if (!glues.isEmpty()) {
            response.setAdditionalResourceRecords(glues);
        }
    }

    private static List<Record<? extends Data>> findGlues(DnsName name, List<Record<? extends Data>> records) {
        List<Record<? extends Data>> glues = new ArrayList<>();
        for (Record<? extends Data> record : records) {
            if (record.name.equals(name)) {
                if (record.type == TYPE.CNAME) {
                    glues.addAll(findGlues(((CNAME) record.payloadData).target, records));
                } else if (record.type == TYPE.A || record.type == TYPE.AAAA) {
                    glues.add(record);
                }
            }
        }
        return glues;
    }

    @SuppressWarnings("unchecked")
    public static DnsWorld applyStubRecords(AbstractDnsClient client, Record<? extends Data>... records) {
        DnsWorld world = new DnsWorld();
        client.setDataSource(world);
        for (Record<? extends Data> record : records) {
            DnsMessage.Builder request = client.buildMessage(new Question(record.name, record.type, record.clazz, record.unicastQuery));
            request.setRecursionDesired(true);
            DnsMessage.Builder response = DnsMessage.builder();
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
        Inet4Address inet4Address = InetAddressUtil.ipv4From(nsIp);
        try {
            return zone(zoneName, InetAddress.getByAddress(nsName, inet4Address.getAddress()), records);
        } catch (UnknownHostException e) {
            // This will never happen, as we already ensured the validity of the IP address by using parseIpV4()
            throw new RuntimeException(e);
        }
    }

    public static Zone zone(String zoneName, InetAddress address, List<Record<? extends Data>> records) {
        return new Zone(zoneName, address, records);
    }

    public static <D extends Data> Record<D> record(String name, long ttl, D data) {
        return new Record<D>(name, data.getType(), CLASS.IN, ttl, data, false);
    }

    public static <D extends Data> Record<D> record(DnsName name, long ttl, D data) {
        return new Record<D>(name, data.getType(), CLASS.IN, ttl, data, false);
    }

    public static <D extends Data> Record<D> record(String name, D data) {
        return record(name, 3600, data);
    }

    public static <D extends Data> Record<D> record(DnsName name, D data) {
        return record(name, 3600, data);
    }

    public static A a(byte[] ip) {
        return new A(ip);
    }

    public static A a(CharSequence ipCharSequence) {
        return new A(ipCharSequence);
    }

    public static AAAA aaaa(byte[] ip) {
        return new AAAA(ip);
    }

    public static AAAA CharSequence(CharSequence ipCharSequence) {
        return new AAAA(ipCharSequence);
    }

    public static CNAME cname(String name) {
        return cname(DnsName.from(name));
    }

    public static CNAME cname(DnsName name) {
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
        return mx(priority, DnsName.from(name));
    }

    public static MX mx(int priority, DnsName name) {
        return new MX(priority, name);
    }

    public static MX mx(String name) {
        return mx(10, name);
    }

    public static NS ns(String name) {
        return ns(DnsName.from(name));
    }

    public static NS ns(DnsName name) {
        return new NS(name);
    }

    public static NSEC nsec(String next, TYPE... types) {
        return nsec(DnsName.from(next), types);
    }

    public static NSEC nsec(DnsName next, TYPE... types) {
        List<TYPE> typesList = Arrays.asList(types);
        return new NSEC(next, typesList);
    }

    public static NSEC3 nsec3(byte hashAlgorithm, byte flags, int iterations, byte[] salt, byte[] nextHashed, TYPE... types) {
        List<TYPE> typesList = Arrays.asList(types);
        return new NSEC3(hashAlgorithm, flags, iterations, salt, nextHashed, typesList);
    }

    public static RRSIG rrsig(TYPE typeCovered, SignatureAlgorithm algorithm, int labels, long originalTtl, Date signatureExpiration,
                              Date signatureInception, int keyTag, String signerName, byte[] signature) {
        return rrsig(typeCovered, algorithm, (byte) labels, originalTtl, signatureExpiration,
                signatureInception, keyTag, DnsName.from(signerName), signature);
    }

    public static RRSIG rrsig(TYPE typeCovered, SignatureAlgorithm algorithm, int labels, long originalTtl,
            Date signatureExpiration, Date signatureInception, int keyTag, DnsName signerName, byte[] signature) {
        return new RRSIG(typeCovered, algorithm, (byte) labels, originalTtl, signatureExpiration, signatureInception,
                keyTag, signerName, signature);
    }

    public static RRSIG rrsig(TYPE typeCovered, int algorithm,
            int labels, long originalTtl, Date signatureExpiration,
            Date signatureInception, int keyTag, String signerName,
            byte[] signature) {
        return rrsig(typeCovered, algorithm, (byte) labels,
                originalTtl, signatureExpiration, signatureInception, keyTag,
                DnsName.from(signerName), signature);
    }

    public static RRSIG rrsig(TYPE typeCovered, int algorithm,
            int labels, long originalTtl, Date signatureExpiration,
            Date signatureInception, int keyTag, DnsName signerName,
            byte[] signature) {
        return new RRSIG(typeCovered, algorithm, (byte) labels,
                originalTtl, signatureExpiration, signatureInception, keyTag,
                signerName, signature);
    }

    public static SOA soa(String mname, String rname, long serial, int refresh, int retry, int expire, long minimum) {
        return soa(DnsName.from(mname), DnsName.from(rname), serial, refresh, retry, expire, minimum);
    }

    public static SOA soa(DnsName mname, DnsName rname, long serial, int refresh, int retry, int expire, long minimum) {
        return new SOA(mname, rname, serial, refresh, retry, expire, minimum);
    }

    public static SRV srv(int priority, int weight, int port, String name) {
        return srv(priority, weight, port, DnsName.from(name));
    }

    public static SRV srv(int priority, int weight, int port, DnsName name) {
        return new SRV(priority, weight, port, name);
    }

    public static SRV srv(int port, String name) {
        return srv(10, 10, port, name);
    }

    public RrSet lookupRrSetFor(DnsName name, TYPE type) {
        Map<TYPE, RrSet> zoneData = worldData.get(name);
        if (zoneData == null) {
            return null;
        }

        return zoneData.get(type);
    }

    public InetAddress lookupSingleAuthoritativeNameserverForZone(DnsName zone) {
        if (zone.isRootLabel()) {
            return DnsRootServer.getIpv4RootServerById('a');
        }

        RrSet nsRrSet = lookupRrSetFor(zone, TYPE.NS);
        if (nsRrSet == null) {
            throw new IllegalStateException();
        }

        @SuppressWarnings("unchecked")
        Record<NS> nsRecord = (Record<NS>) nsRrSet.records.iterator().next();

        RrSet aRrSet = lookupRrSetFor(nsRecord.name, TYPE.A);
        if (aRrSet == null) {
            throw new IllegalStateException();
        }

        @SuppressWarnings("unchecked")
        Record<A> aRecord = (Record<A>) aRrSet.records.iterator().next();

        try {
            return InetAddress.getByAddress(nsRecord.name.toString(), aRecord.payloadData.getIp());
        } catch (UnknownHostException e) {
            throw new AssertionError(e);
        }
    }
}
