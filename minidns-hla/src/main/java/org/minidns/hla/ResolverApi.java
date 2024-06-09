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
package org.minidns.hla;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;

import org.minidns.AbstractDnsClient;
import org.minidns.DnsClient;
import org.minidns.dnslabel.DnsLabel;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsname.DnsName;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.hla.srv.SrvProto;
import org.minidns.hla.srv.SrvService;
import org.minidns.hla.srv.SrvServiceProto;
import org.minidns.hla.srv.SrvType;
import org.minidns.iterative.ReliableDnsClient;
import org.minidns.record.Data;
import org.minidns.record.PTR;
import org.minidns.record.SRV;
import org.minidns.record.Record.TYPE;

/**
 * The high-level MiniDNS resolving API. It is designed to be easy to use.
 * <p>
 * A simple exammple how to resolve the IPv4 address of a given domain:
 * </p>
 * <pre>
 * {@code
 * ResolverResult<A> result = DnssecResolverApi.INSTANCE.resolve("verteiltesysteme.net", A.class);
 * if (!result.wasSuccessful()) {
 *   RESPONSE_CODE responseCode = result.getResponseCode();
 *   // Perform error handling.
 *   …
 *   return;
 * }
 * if (!result.isAuthenticData()) {
 *   // Response was not secured with DNSSEC.
 *   …
 *   return;
 * }
 * Set<A> answers = result.getAnswers();
 * for (A a : answers) {
 *   InetAddress inetAddress = a.getInetAddress();
 *   // Do someting with the InetAddress, e.g. connect to.
 *   …
 * }
 * }
 * </pre>
 * <p>
 * MiniDNS also supports SRV resource records as first class citizens:
 * </p>
 * <pre>
 * {@code
 * SrvResolverResult result = DnssecResolverApi.INSTANCE.resolveSrv(SrvType.xmpp_client, "example.org")
 * if (!result.wasSuccessful()) {
 *   RESPONSE_CODE responseCode = result.getResponseCode();
 *   // Perform error handling.
 *   …
 *   return;
 * }
 * if (!result.isAuthenticData()) {
 *   // Response was not secured with DNSSEC.
 *   …
 *   return;
 * }
 * List<ResolvedSrvRecord> srvRecords = result.getSortedSrvResolvedAddresses();
 * // Loop over the domain names pointed by the SRV RR. MiniDNS will return the list
 * // correctly sorted by the priority and weight of the related SRV RR.
 * for (ResolvedSrvRecord srvRecord : srvRecord) {
 *   // Loop over the Internet Address RRs resolved for the SRV RR. The order of
 *   // the list depends on the prefered IP version setting of MiniDNS.
 *   for (InternetAddressRR inetAddressRR : srvRecord.addresses) {
 *     InetAddress inetAddress = inetAddressRR.getInetAddress();
 *     int port = srvAddresses.port;
 *     // Try to connect to inetAddress at port.
 *     …
 *   }
 * }
 * }
 * </pre>
 *
 * @author Florian Schmaus
 *
 */
public class ResolverApi {

    public static final ResolverApi INSTANCE = new ResolverApi(new ReliableDnsClient());

    private final AbstractDnsClient dnsClient;

    public ResolverApi(AbstractDnsClient dnsClient) {
        this.dnsClient = dnsClient;
    }

    public final <D extends Data> ResolverResult<D> resolve(String name, Class<D> type) throws IOException {
        return resolve(DnsName.from(name), type);
    }

    public final <D extends Data> ResolverResult<D> resolve(DnsName name, Class<D> type) throws IOException {
        TYPE t = TYPE.getType(type);
        Question q = new Question(name, t);
        return resolve(q);
    }

    public <D extends Data> ResolverResult<D> resolve(Question question) throws IOException {
        DnsQueryResult dnsQueryResult = dnsClient.query(question);

        return new ResolverResult<D>(question, dnsQueryResult, null);
    }

    public SrvResolverResult resolveSrv(SrvType type, String serviceName) throws IOException {
        return resolveSrv(type.service, type.proto, DnsName.from(serviceName));
    }

    public SrvResolverResult resolveSrv(SrvType type, DnsName serviceName) throws IOException {
        return resolveSrv(type.service, type.proto, serviceName);
    }

    public SrvResolverResult resolveSrv(SrvService service, SrvProto proto, String name) throws IOException {
        return resolveSrv(service.dnsLabel, proto.dnsLabel, DnsName.from(name));
    }

    public SrvResolverResult resolveSrv(SrvService service, SrvProto proto, DnsName name) throws IOException {
        return resolveSrv(service.dnsLabel, proto.dnsLabel, name);
    }

    public SrvResolverResult resolveSrv(DnsLabel service, DnsLabel proto, DnsName name) throws IOException {
        SrvServiceProto srvServiceProto = new SrvServiceProto(service, proto);
        return resolveSrv(name, srvServiceProto);
    }

    public SrvResolverResult resolveSrv(String name) throws IOException {
        return resolveSrv(DnsName.from(name));
    }

    public ResolverResult<PTR> reverseLookup(CharSequence inetAddressCs) throws IOException {
        InetAddress inetAddress = InetAddress.getByName(inetAddressCs.toString());
        return reverseLookup(inetAddress);
    }

    public ResolverResult<PTR> reverseLookup(InetAddress inetAddress) throws IOException {
        if (inetAddress instanceof Inet4Address) {
            return reverseLookup((Inet4Address) inetAddress);
        } else if (inetAddress instanceof Inet6Address) {
            return reverseLookup((Inet6Address) inetAddress);
        } else {
            throw new IllegalArgumentException("The given InetAddress '" + inetAddress + "' is neither of type Inet4Address or Inet6Address");
        }
    }

    public ResolverResult<PTR> reverseLookup(Inet4Address inet4Address) throws IOException {
        Question question = DnsClient.getReverseIpLookupQuestionFor(inet4Address);
        return resolve(question);
    }

    public ResolverResult<PTR> reverseLookup(Inet6Address inet6Address) throws IOException {
        Question question = DnsClient.getReverseIpLookupQuestionFor(inet6Address);
        return resolve(question);
    }

    /**
     * Resolve the {@link SRV} resource record for the given name. After ensuring that the resolution was successful
     * with {@link SrvResolverResult#wasSuccessful()} , and, if DNSSEC was used, that the results could be verified with
     * {@link SrvResolverResult#isAuthenticData()}, simply use {@link SrvResolverResult#getSortedSrvResolvedAddresses()} to
     * retrieve the resolved IP addresses.
     * <p>
     * The name of SRV records is "_[service]._[protocol].[serviceDomain]", for example "_xmpp-client._tcp.example.org".
     * </p>
     *
     * @param srvDnsName the name to resolve.
     * @return a <code>SrvResolverResult</code> instance which can be used to retrieve the IP addresses.
     * @throws IOException if an IO exception occurs.
     */
    public SrvResolverResult resolveSrv(DnsName srvDnsName) throws IOException {
        final int labelCount = srvDnsName.getLabelCount();
        if (labelCount < 3) {
            throw new IllegalArgumentException();
        }

        DnsLabel service = srvDnsName.getLabel(labelCount - 1);
        DnsLabel proto = srvDnsName.getLabel(labelCount - 2);
        DnsName name = srvDnsName.stripToLabels(labelCount - 2);

        SrvServiceProto srvServiceProto = new SrvServiceProto(service, proto);

        return resolveSrv(name, srvServiceProto);
    }

    /**
     * Resolve the {@link SRV} resource record for the given service name, service and protcol. After ensuring that the
     * resolution was successful with {@link SrvResolverResult#wasSuccessful()} , and, if DNSSEC was used, that the
     * results could be verified with {@link SrvResolverResult#isAuthenticData()}, simply use
     * {@link SrvResolverResult#getSortedSrvResolvedAddresses()} to retrieve the resolved IP addresses.
     *
     * @param name the DNS name of the service.
     * @param srvServiceProto the service and protocol to lookup.
     * @return a <code>SrvResolverResult</code> instance which can be used to retrieve the IP addresses.
     * @throws IOException if an I/O error occurs.
     */
    public SrvResolverResult resolveSrv(DnsName name, SrvServiceProto srvServiceProto) throws IOException {
        DnsName srvDnsName = DnsName.from(srvServiceProto.service, srvServiceProto.proto, name);
        ResolverResult<SRV> result = resolve(srvDnsName, SRV.class);

        return new SrvResolverResult(result, srvServiceProto, this);
    }

    public final AbstractDnsClient getClient() {
        return dnsClient;
    }
}
