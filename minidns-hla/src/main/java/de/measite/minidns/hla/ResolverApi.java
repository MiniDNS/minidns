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
package de.measite.minidns.hla;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.DNSName;
import de.measite.minidns.Question;
import de.measite.minidns.AbstractDNSClient.IpVersionSetting;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.iterative.ReliableDNSClient;
import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.InternetAddressRR;
import de.measite.minidns.record.SRV;
import de.measite.minidns.util.SrvUtil;

public class ResolverApi {

    public static final ResolverApi INSTANCE = new ResolverApi(new ReliableDNSClient());

    private final AbstractDNSClient dnsClient;

    public ResolverApi(AbstractDNSClient dnsClient) {
        this.dnsClient = dnsClient;
    }

    public final <D extends Data> ResolverResult<D> resolve(String name, Class<D> type) throws IOException {
        return resolve(DNSName.from(name), type);
    }

    public final <D extends Data> ResolverResult<D> resolve(DNSName name, Class<D> type) throws IOException {
        TYPE t = TYPE.getType(type);
        Question q = new Question(name, t);
        return resolve(q);
    }

    public <D extends Data> ResolverResult<D> resolve(Question question) throws IOException {
        DNSMessage dnsMessage = dnsClient.query(question);

        return new ResolverResult<D>(question, dnsMessage, null);
    }

    public List<ResolvedSrvAddresses> resolveSrv(SrvType type, String serviceName) throws IOException {
        return resolveSrv(type.service, type.proto, DNSName.from(serviceName));
    }

    public List<ResolvedSrvAddresses> resolveSrv(SrvType type, DNSName serviceName) throws IOException {
        return resolveSrv(type.service, type.proto, serviceName);
    }

    public List<ResolvedSrvAddresses> resolveSrv(SrvService service, SrvProto proto, String name) throws IOException {
        return resolveSrv(service.dnsName, proto.dnsName, DNSName.from(name));
    }

    public List<ResolvedSrvAddresses> resolveSrv(SrvService service, SrvProto proto, DNSName name) throws IOException {
        return resolveSrv(service.dnsName, proto.dnsName, name);
    }

    public List<ResolvedSrvAddresses> resolveSrv(DNSName service, DNSName proto, DNSName name) throws IOException {
        DNSName srvRrName = DNSName.from(service, proto, name);
        return resolveSrv(srvRrName);
    }

    public List<ResolvedSrvAddresses> resolveSrv(String name) throws IOException {
        return resolveSrv(DNSName.from(name));
    }

    /**
     * Resolve the {@link SRV} resource record for the given name. The returned list is sorted according to the priority
     * and weight of the resolved SRV records.
     * <p>
     * The name of SRV records is "_[service]._[protocol].[serviceDomain]", for example "_xmpp-client._tcp.example.org".
     * </p>
     *
     * @param name the name to resolve.
     * @return a list of resolved SRV addresses sorted by priority and weight.
     * @throws IOException if an IO exception occurs.
     */
    public List<ResolvedSrvAddresses> resolveSrv(DNSName name) throws IOException {

        ResolverResult<SRV> result = resolve(name, SRV.class);
        if (!result.wasSuccessful()) {
            return null;
        }

        if (result.hasUnverifiedReasons()) {
            return null;
        }

        List<SRV> srvRecords = SrvUtil.sortSrvRecords(result.getAnswers());

        IpVersionSetting ipVersion = getClient().getPreferedIpVersion();
        List<ResolvedSrvAddresses> res = new ArrayList<>(srvRecords.size());
        for (SRV srvRecord : srvRecords) {
            Set<A> aRecords = Collections.emptySet();
            if (ipVersion.v4) {
                ResolverResult<A> aRecordResult = resolve(srvRecord.name, A.class);
                if (aRecordResult.wasSuccessful() && !aRecordResult.hasUnverifiedReasons()) {
                    aRecords = aRecordResult.getAnswers();
                }
            }

            Set<AAAA> aaaaRecords = Collections.emptySet();
            if (ipVersion.v6) {
                ResolverResult<AAAA> aaaaRecordResult = resolve(srvRecord.name, AAAA.class);
                if (aaaaRecordResult.wasSuccessful() && !aaaaRecordResult.hasUnverifiedReasons()) {
                    aaaaRecords = aaaaRecordResult.getAnswers();
                }
            }

            if (aRecords.isEmpty() && aaaaRecords.isEmpty()) {
                // TODO Possibly check for (C|D)NAME usage and throw a meaningful exception that it is not allowed for
                // the target of an SRV to be an alias as per RFC 2782.
                /*
                ResolverResult<CNAME> cnameRecordResult = resolve(srvRecord.name, CNAME.class);
                if (cnameRecordResult.wasSuccessful()) {
                }
                */
                continue;
            }

            List<InternetAddressRR> srvAddresses = new ArrayList<>(aRecords.size() + aaaaRecords.size());
            switch (ipVersion) {
            case v4only:
                for (A a : aRecords) {
                    srvAddresses.add(a);
                }
                break;
            case v6only:
                for (AAAA aaaa : aaaaRecords) {
                    srvAddresses.add(aaaa);
                }
                break;
            case v4v6:
                for (A a : aRecords) {
                    srvAddresses.add(a);
                }
                for (AAAA aaaa : aaaaRecords) {
                    srvAddresses.add(aaaa);
                }
                break;
            case v6v4:
                for (AAAA aaaa : aaaaRecords) {
                    srvAddresses.add(aaaa);
                }
                for (A a : aRecords) {
                    srvAddresses.add(a);
                }
                break;
            }

            ResolvedSrvAddresses resolvedSrvAddresses = new ResolvedSrvAddresses(name, srvRecord, srvAddresses);
            res.add(resolvedSrvAddresses);
        }

        return res;
    }

    public static class ResolvedSrvAddresses {
        public final DNSName name;
        public final SRV srv;
        public final List<InternetAddressRR> addresses;

        private ResolvedSrvAddresses(DNSName name, SRV srv, List<InternetAddressRR> addresses) {
            this.name = name;
            this.srv = srv;
            this.addresses = Collections.unmodifiableList(addresses);
        }
    }

    public final AbstractDNSClient getClient() {
        return dnsClient;
    }
}
