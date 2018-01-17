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
package de.measite.minidns.hla;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import de.measite.minidns.AbstractDNSClient.IpVersionSetting;
import de.measite.minidns.DNSName;
import de.measite.minidns.MiniDNSException.NullResultException;
import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.InternetAddressRR;
import de.measite.minidns.record.SRV;
import de.measite.minidns.util.SrvUtil;

public class SrvResolverResult extends ResolverResult<SRV> {

    private final ResolverApi resolver;
    private final IpVersionSetting ipVersion;

    private List<ResolvedSrvRecord> sortedSrvResolvedAddresses;

    SrvResolverResult(ResolverResult<SRV> srvResult, ResolverApi resolver) throws NullResultException {
        super(srvResult.question, srvResult.answer, srvResult.unverifiedReasons);
        this.resolver = resolver;
        this.ipVersion = resolver.getClient().getPreferedIpVersion();
    }

    public List<ResolvedSrvRecord> getSortedSrvResolvedAddresses() throws IOException {
        if (sortedSrvResolvedAddresses != null) {
            return sortedSrvResolvedAddresses;
        }

        throwIseIfErrorResponse();

        List<SRV> srvRecords = SrvUtil.sortSrvRecords(getAnswers());

        List<ResolvedSrvRecord> res = new ArrayList<>(srvRecords.size());
        for (SRV srvRecord : srvRecords) {
            ResolverResult<A> aRecordsResult = null;
            ResolverResult<AAAA> aaaaRecordsResult = null;
            Set<A> aRecords = Collections.emptySet();
            if (ipVersion.v4) {
                aRecordsResult = resolver.resolve(srvRecord.target, A.class);
                if (aRecordsResult.wasSuccessful() && !aRecordsResult.hasUnverifiedReasons()) {
                    aRecords = aRecordsResult.getAnswers();
                }
            }

            Set<AAAA> aaaaRecords = Collections.emptySet();
            if (ipVersion.v6) {
                aaaaRecordsResult = resolver.resolve(srvRecord.target, AAAA.class);
                if (aaaaRecordsResult.wasSuccessful() && !aaaaRecordsResult.hasUnverifiedReasons()) {
                    aaaaRecords = aaaaRecordsResult.getAnswers();
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

            ResolvedSrvRecord resolvedSrvAddresses = new ResolvedSrvRecord(question.name, srvRecord, srvAddresses,
                    aRecordsResult, aaaaRecordsResult);
            res.add(resolvedSrvAddresses);
        }

        sortedSrvResolvedAddresses = res;

        return res;
    }

    public static class ResolvedSrvRecord {
        public final DNSName name;
        public final SRV srv;
        public final List<InternetAddressRR> addresses;
        public final ResolverResult<A> aRecordsResult;
        public final ResolverResult<AAAA> aaaaRecordsResult;

        /**
         * The port announced by the SRV RR. This is simply a shortcut for <code>srv.port</code>.
         */
        public final int port;

        private ResolvedSrvRecord(DNSName name, SRV srv, List<InternetAddressRR> addresses, ResolverResult<A> aRecordsResult, ResolverResult<AAAA> aaaaRecordsResult) {
            this.name = name;
            this.srv = srv;
            this.addresses = Collections.unmodifiableList(addresses);
            this.port = srv.port;
            this.aRecordsResult = aRecordsResult;
            this.aaaaRecordsResult = aaaaRecordsResult;
        }
    }
}
