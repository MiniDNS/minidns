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
package org.minidns.dnssec;

import org.minidns.DnsWorld;
import org.minidns.DnsWorld.AddressedAnswerResponse;
import org.minidns.DnsWorld.Zone;
import org.minidns.cache.LruCache;
import org.minidns.constants.DnssecConstants.DigestAlgorithm;
import org.minidns.constants.DnssecConstants.SignatureAlgorithm;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsname.DnsName;
import org.minidns.dnssec.DnssecValidationFailedException.AuthorityDoesNotContainSoa;
import org.minidns.dnssec.DnssecWorld.DnssecData;
import org.minidns.dnssec.DnssecWorld.SignedRRSet;
import org.minidns.iterative.ReliableDnsClient.Mode;
import org.minidns.record.A;
import org.minidns.record.CNAME;
import org.minidns.record.DNAME;
import org.minidns.record.DNSKEY;
import org.minidns.record.DS;
import org.minidns.record.Data;
import org.minidns.record.RRSIG;
import org.minidns.record.Record;
import org.minidns.record.Record.TYPE;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.minidns.DnsWorld.a;
import static org.minidns.DnsWorld.applyZones;
import static org.minidns.DnsWorld.cname;
import static org.minidns.DnsWorld.dnskey;
import static org.minidns.DnsWorld.ns;
import static org.minidns.DnsWorld.nsec;
import static org.minidns.DnsWorld.record;
import static org.minidns.DnsWorld.rootZone;
import static org.minidns.DnsWorld.rrsig;
import static org.minidns.DnsWorld.soa;
import static org.minidns.DnsWorld.zone;
import static org.minidns.dnssec.DnssecWorld.addNsec;
import static org.minidns.dnssec.DnssecWorld.calculateDsDigest;
import static org.minidns.dnssec.DnssecWorld.dlv;
import static org.minidns.dnssec.DnssecWorld.ds;
import static org.minidns.dnssec.DnssecWorld.merge;
import static org.minidns.dnssec.DnssecWorld.publicKey;
import static org.minidns.dnssec.DnssecWorld.rrsigRecord;
import static org.minidns.dnssec.DnssecWorld.selfSignDnskeyRrSet;
import static org.minidns.dnssec.DnssecWorld.sign;
import static org.minidns.dnssec.DnssecWorld.signedRootZone;
import static org.minidns.dnssec.DnssecWorld.signedZone;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

// TODO: Make selfSignDnskeyRrset() part of signedZone() and remove it from all tests

public class DnssecClientTest {
    private static SignatureAlgorithm algorithm = SignatureAlgorithm.RSASHA256;
    private static DigestAlgorithm digestType = DigestAlgorithm.SHA1;
    private static PrivateKey rootPrivateKSK;
    private static DNSKEY rootKSK;
    private static PrivateKey rootPrivateZSK;
    private static DNSKEY rootZSK;
    private static DNSKEY comKSK;
    private static DNSKEY comZSK;
    private static PrivateKey comPrivateZSK;
    private static PrivateKey comPrivateKSK;

    static {
        DnssecData rootDnssecData = DnssecWorld.getDnssecDataFor("");
        rootPrivateKSK = rootDnssecData.privateKsk;
        rootKSK = rootDnssecData.ksk;
        rootPrivateZSK = rootDnssecData.privateZsk;
        rootZSK = rootDnssecData.zsk;

        DnssecData comDnssecData = DnssecWorld.getDnssecDataFor("com");
        comPrivateKSK = comDnssecData.privateKsk;
        comKSK = comDnssecData.ksk;
        comPrivateZSK = comDnssecData.privateZsk;
        comZSK = comDnssecData.zsk;
    }

    public static DnssecClient constructDnssecClient() {
        DnssecClient client = new DnssecClient(new LruCache(0));
        client.addSecureEntryPoint(DnsName.ROOT, rootKSK.getKey());
        client.setMode(Mode.iterativeOnly);
        return client;
    }

    void checkCorrectExampleMessage(DnsMessage message) {
        List<Record<? extends Data>> answers = message.answerSection;
        assertEquals(1, answers.size());
        assertEquals(Record.TYPE.A, answers.get(0).type);
        assertArrayEquals(new byte[] {1, 1, 1, 2}, ((A) answers.get(0).payloadData).getIp());
    }

    @Test
    public void testBasicValid() throws IOException {
        DnssecClient client = constructDnssecClient();
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertTrue(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNoSEPAtKSK() throws IOException {
        DnssecClient client = constructDnssecClient();
        DNSKEY comKSK = dnskey(DNSKEY.FLAG_ZONE, algorithm, publicKey(algorithm, comPrivateKSK));
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertTrue(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testSingleZSK() throws IOException {
        DnssecClient client = constructDnssecClient();
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK)),
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertTrue(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testMissingDelegation() throws IOException {
        DnssecClient client = constructDnssecClient();
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );

        assertThrows(AuthorityDoesNotContainSoa.class, () ->
            client.queryDnssec("example.com", Record.TYPE.A)
        );
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUnsignedRoot() throws IOException {
        DnssecClient client = constructDnssecClient();
        applyZones(client,
                rootZone(
                        record("com", ds("com", digestType, comKSK)),
                        record("com", ns("ns.com")),
                        record("ns.com", a("1.1.1.1"))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertFalse(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNoRootSecureEntryPoint() throws IOException {
        DnssecClient client = constructDnssecClient();
        client.clearSecureEntryPoints();
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertFalse(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);
        assertEquals(1, result.getUnverifiedReasons().size());
        assertTrue(result.getUnverifiedReasons().iterator().next() instanceof DnssecUnverifiedReason.NoRootSecureEntryPointReason);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUnsignedZone() throws IOException {
        DnssecClient client = constructDnssecClient();
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), zone("com", "ns.com", "1.1.1.1",
                        record("example.com", a("1.1.1.2"))
                )
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertFalse(result.isAuthenticData());
        DnsMessage message = result.dnsQueryResult.response;
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testInvalidDNSKEY() throws IOException {
        DnssecClient client = constructDnssecClient();
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );

        assertThrows(DnssecValidationFailedException.class, () ->
            client.query("example.com", Record.TYPE.A)
        );
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNoDNSKEY() throws IOException {
        DnssecClient client = constructDnssecClient();
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );

        assertThrows(DnssecValidationFailedException.class, () ->
            client.query("example.com", Record.TYPE.A)
        );
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testInvalidRRSIG() throws IOException, NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        DnssecClient client = constructDnssecClient();
        Record<RRSIG> invalidRrSig = rrsigRecord(comZSK, "com", comPrivateZSK, algorithm, record("example.com", a("1.1.1.2")));
        RRSIG soonToBeInvalidRrSig = invalidRrSig.payloadData;
        Field signature = soonToBeInvalidRrSig.getClass().getDeclaredField("signature");
        signature.setAccessible(true);
        byte[] signatureMod = (byte[]) signature.get(soonToBeInvalidRrSig);

        // Change the signature a little bit so that it becomes invalid.
        signatureMod[signatureMod.length / 2]++;

        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), zone("com", "ns.com", "1.1.1.1",
                        record("com", comKSK),
                        record("com", comZSK),
                        record("example.com", a("1.1.1.2")),
                        invalidRrSig
                )
        );

        assertThrows(DnssecValidationFailedException.class, () ->
            client.query("example.com", Record.TYPE.A)
        );
    }

    @SuppressWarnings({"unchecked", "JavaUtilDate"})
    @Test
    public void testUnknownAlgorithm() throws IOException {
        DnssecClient client = constructDnssecClient();
        Date signatureExpiration = new Date(System.currentTimeMillis() + 14 * 24 * 60 * 60 * 1000);
        Date signatureInception = new Date(System.currentTimeMillis() - 14 * 24 * 60 * 60 * 1000);
        RRSIG unknownRrsig = rrsig(Record.TYPE.A, 213, 2, 3600, signatureExpiration, signatureInception, comZSK.getKeyTag(), "com", new byte[0]);
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), zone("com", "ns.com", "1.1.1.1",
                        record("com", comKSK),
                        record("com", comZSK),
                        record("example.com", a("1.1.1.2")),
                        record("example.com", unknownRrsig)
                )
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertFalse(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testInvalidDelegation() throws IOException {
        DnssecClient client = constructDnssecClient();
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds(comKSK.getKeyTag(), algorithm, digestType, new byte[0]))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );

        assertThrows(DnssecValidationFailedException.class, () ->
            client.query("example.com", Record.TYPE.A)
        );
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUnknownDelegationDigestType() throws IOException {
        DnssecClient client = constructDnssecClient();
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds(comKSK.getKeyTag(), algorithm, (byte) 213, new byte[0]))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertFalse(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings({"unchecked", "JavaUtilDate"})
    @Test
    public void testSignatureOutOfDate() throws IOException {
        DnssecClient client = constructDnssecClient();
        Date signatureExpiration = new Date(System.currentTimeMillis() - 14 * 24 * 60 * 60 * 1000);
        Date signatureInception = new Date(System.currentTimeMillis() - 28L * 24L * 60L * 60L * 1000L);
        RRSIG outOfDateSig = rrsig(Record.TYPE.A, algorithm, 2, 3600, signatureExpiration, signatureInception, comZSK.getKeyTag(), "com", new byte[0]);
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comPrivateZSK, outOfDateSig,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertFalse(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings({"unchecked", "JavaUtilDate"})
    @Test
    public void testSignatureInFuture() throws IOException {
        DnssecClient client = constructDnssecClient();
        Date signatureExpiration = new Date(System.currentTimeMillis() + 28L * 24L * 60L * 60L * 1000L);
        Date signatureInception = new Date(System.currentTimeMillis() + 14 * 24 * 60 * 60 * 1000);
        RRSIG outOfDateSig = rrsig(Record.TYPE.A, algorithm, 2, 3600, signatureExpiration, signatureInception, comZSK.getKeyTag(), "com", new byte[0]);
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comPrivateZSK, outOfDateSig,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertFalse(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testValidNSEC() throws Exception {
        DnssecClient client = constructDnssecClient();
        DnsWorld world = applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DnsMessage.Builder nsecMessage = DnsMessage.builder();
        List<Record<? extends Data>> records = DnssecWorld.merge(
                                sign(comZSK, "com", comPrivateZSK, algorithm,
                                        record("example.com", nsec("www.example.com", Record.TYPE.A))),
                                sign(comZSK, "com", comPrivateZSK, algorithm,
                                        record("example.com", soa("sns.dns.icann.org", "noc.dns.icann.org", 2015081265, 7200, 3600, 1209600, 3600))));
        nsecMessage.setNameserverRecords(records);
        nsecMessage.setAuthoritativeAnswer(true);
        world.addPreparedResponse(new DnssecWorld.AddressedNsecResponse(InetAddress.getByAddress("ns.com", new byte[] {1, 1, 1, 1}), nsecMessage.build()));
        DnssecQueryResult result = client.queryDnssec("nsec.example.com", Record.TYPE.A);
        // TODO: The setSripSignatureRecords() call could probably be removed. It does not appear to server any purpose here.
        client.setStripSignatureRecords(false);
        DnsMessage message = result.synthesizedResponse;
        assertEquals(0, message.answerSection.size());
        assertTrue(message.authenticData);
    }

    /**
     * Zone 'com.' has no DS in the root zone. Hence, in order to verify the results of RRs under 'com.' a DLV has to
     * been used.
     *
     * @throws IOException in case of an I/O error.
     */
    @Test
    public void testValidDLV() throws IOException {
        DnssecClient client = constructDnssecClient();
        DnsWorld dnsWorld = applyZones(client,
                signedRootZone(
                        selfSignDnskeyRrSet(""),
                        sign("",
                                ds("dlv")),
                        sign("",
                                record("dlv", ns("ns.com"))),
                        sign("",
                                record("com", ns("ns.com"))),
                        sign("",
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        selfSignDnskeyRrSet("com"),
                        sign("com",
                                record("example.com", a("1.1.1.2")))
                ), signedZone("dlv", "ns.com", "1.1.1.1",
                        selfSignDnskeyRrSet("dlv"),
                        sign("dlv",
                                record("com.dlv", dlv("com", digestType, comKSK)))
                )
        );
        // Add NSEC which proves that there is no DS record for 'com.'. Note that the prove comes from the parental zone
        // nameserver in case of DS RRs.
        addNsec(dnsWorld, "", "a.root-servers.net", "com", "dlv", TYPE.NS);

        client.configureLookasideValidation(DnsName.from("dlv"));

        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertTrue(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);

        client.disableLookasideValidation();
        result = client.queryDnssec("example.com", Record.TYPE.A);
        assertFalse(result.isAuthenticData());
        message = result.synthesizedResponse;
        checkCorrectExampleMessage(message);
    }

    // Query the A RRs of the given name, which are answered by the nameserver of the 'com' zone with the given signed
    // and unsigned RRs.
    private static DnssecQueryResult queryWithUnsignedRecords(String name, List<Record<? extends Data>> unsignedRecords,
            SignedRRSet... signedRrSets) throws IOException {
        DnssecClient client = constructDnssecClient();
        SignedRRSet[] comRrSets = new SignedRRSet[signedRrSets.length + 1];
        comRrSets[0] = selfSignDnskeyRrSet("com");
        System.arraycopy(signedRrSets, 0, comRrSets, 1, signedRrSets.length);
        DnsWorld dnsWorld = applyZones(client,
                signedRootZone(
                        selfSignDnskeyRrSet(""),
                        sign("",
                                ds("com")),
                        sign("",
                                record("com", ns("ns.com"))),
                        sign("",
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1", comRrSets)
        );

        List<Record<? extends Data>> answers = merge(signedRrSets);
        answers.addAll(unsignedRecords);
        DnsMessage request = DnsMessage.builder()
                .setQuestion(new Question(name, TYPE.A))
                .build();
        DnsMessage response = DnsMessage.builder()
                .setAnswers(answers)
                .setAuthoritativeAnswer(true)
                .build();
        InetAddress comNameserver = InetAddress.getByAddress("ns.com", new byte[] {1, 1, 1, 1});
        dnsWorld.addPreparedResponse(new AddressedAnswerResponse(comNameserver, request, response));

        return client.queryDnssec(name, TYPE.A);
    }

    @Test
    public void testDnameSynthesizedCname() throws IOException {
        DnssecQueryResult result = queryWithUnsignedRecords("www.old.example.com",
                Collections.singletonList(record("www.old.example.com", cname("www.new.example.com"))),
                sign("com",
                        record("old.example.com", new DNAME("new.example.com"))),
                sign("com",
                        record("www.new.example.com", a("1.1.1.2")))
        );
        assertTrue(result.isAuthenticData());
        DnsMessage message = result.synthesizedResponse;
        assertEquals(1, message.filterAnswerSectionBy(CNAME.class).size());
        assertEquals(1, message.filterAnswerSectionBy(A.class).size());
    }

    @Test
    public void testChainedDnameSynthesizedCnames() throws IOException {
        DnssecQueryResult result = queryWithUnsignedRecords("www.a.example.com",
                Arrays.asList(
                        record("www.a.example.com", cname("www.b.example.com")),
                        record("www.b.example.com", cname("www.c.example.com"))),
                sign("com",
                        record("a.example.com", new DNAME("b.example.com"))),
                sign("com",
                        record("b.example.com", new DNAME("c.example.com"))),
                sign("com",
                        record("www.c.example.com", a("1.1.1.2")))
        );
        assertTrue(result.isAuthenticData());
    }

    @Test
    public void testDnameSynthesizedCnameWithWrongTarget() {
        assertThrows(DnssecValidationFailedException.class, () -> queryWithUnsignedRecords("www.old.example.com",
                Collections.singletonList(record("www.old.example.com", cname("www.evil.example.com"))),
                sign("com",
                        record("old.example.com", new DNAME("new.example.com"))),
                sign("com",
                        record("www.evil.example.com", a("1.1.1.2")))
        ));
    }

    @Test
    public void testDnameSynthesizedCnameAtDnameOwner() {
        // A DNAME RR does not redirect its owner name, hence a CNAME RR at the owner can not be synthesized from it.
        assertThrows(DnssecValidationFailedException.class, () -> queryWithUnsignedRecords("old.example.com",
                Collections.singletonList(record("old.example.com", cname("new.example.com"))),
                sign("com",
                        record("old.example.com", new DNAME("new.example.com"))),
                sign("com",
                        record("new.example.com", a("1.1.1.2")))
        ));
    }

    @Test
    public void testDnameSynthesizedCnameOutsideOfDname() {
        assertThrows(DnssecValidationFailedException.class, () -> queryWithUnsignedRecords("www.other.example.com",
                Collections.singletonList(record("www.other.example.com", cname("www.new.example.com"))),
                sign("com",
                        record("old.example.com", new DNAME("new.example.com"))),
                sign("com",
                        record("www.new.example.com", a("1.1.1.2")))
        ));
    }

    @Test
    public void testUnsignedDnameSynthesizedCname() {
        assertThrows(DnssecValidationFailedException.class, () -> queryWithUnsignedRecords("www.old.example.com",
                Arrays.asList(
                        record("old.example.com", new DNAME("new.example.com")),
                        record("www.old.example.com", cname("www.new.example.com"))),
                sign("com",
                        record("www.new.example.com", a("1.1.1.2")))
        ));
    }

    @Test
    public void testDnameDoesNotValidateOtherUnsignedRecords() {
        assertThrows(DnssecValidationFailedException.class, () -> queryWithUnsignedRecords("www.old.example.com",
                Arrays.asList(
                        record("www.old.example.com", cname("www.new.example.com")),
                        record("www.new.example.com", a("1.1.1.3"))),
                sign("com",
                        record("old.example.com", new DNAME("new.example.com"))),
                sign("com",
                        record("www.new.example.com", a("1.1.1.2")))
        ));
    }

    @SuppressWarnings("unchecked")
    private static Zone signedRootZoneDelegatingCom() {
        return signedRootZone(
                sign(rootKSK, "", rootPrivateKSK, algorithm,
                        record("", rootKSK),
                        record("", rootZSK)),
                sign(rootZSK, "", rootPrivateZSK, algorithm,
                        record("com", ds("com", digestType, comKSK))),
                sign(rootZSK, "", rootPrivateZSK, algorithm,
                        record("com", ns("ns.com"))),
                sign(rootZSK, "", rootPrivateZSK, algorithm,
                        record("ns.com", a("1.1.1.1")))
        );
    }

    private static final PrivateKey ROGUE_PRIVATE_KEY = DnssecWorld.generatePrivateKey(algorithm, 1024);
    private static final DNSKEY ROGUE_KEY = dnskey(DNSKEY.FLAG_ZONE | DNSKEY.FLAG_SECURE_ENTRY_POINT, algorithm, publicKey(algorithm, ROGUE_PRIVATE_KEY));

    /**
     * Create an RRSIG RR that claims to be made by comZSK, but which is made with a different private key, and hence is
     * invalid.
     *
     * @param record the record to sign.
     * @return the invalid RRSIG RR.
     */
    @SuppressWarnings("unchecked")
    private static Record<RRSIG> invalidComZskRrsig(Record<? extends Data> record) {
        return rrsigRecord(comZSK, "com", ROGUE_PRIVATE_KEY, algorithm, record);
    }

    @SuppressWarnings("unchecked")
    private static DnssecClient constructDnssecClientWithComZone(List<Record<? extends Data>> comZoneRecords) {
        DnssecClient client = constructDnssecClient();
        List<Record<? extends Data>> records = merge(
                sign(comKSK, "com", comPrivateKSK, algorithm,
                        record("com", comKSK),
                        record("com", comZSK)));
        records.addAll(comZoneRecords);
        applyZones(client,
                signedRootZoneDelegatingCom(),
                zone("com", "ns.com", "1.1.1.1", records)
        );
        return client;
    }

    @Test
    public void testOneOfMultipleRrsigsInvalid() throws IOException {
        Record<A> example = record("example.com", a("1.1.1.2"));
        DnssecClient client = constructDnssecClientWithComZone(Arrays.asList(
                example,
                invalidComZskRrsig(example),
                rrsigRecord(comZSK, "com", comPrivateZSK, algorithm, example)));
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertTrue(result.isAuthenticData());
        checkCorrectExampleMessage(result.synthesizedResponse);
    }

    @Test
    public void testRrsigWithUnknownKeyAlongsideValidRrsig() throws IOException {
        Record<A> example = record("example.com", a("1.1.1.2"));
        DnssecClient client = constructDnssecClientWithComZone(Arrays.asList(
                example,
                rrsigRecord(ROGUE_KEY, "com", ROGUE_PRIVATE_KEY, algorithm, example),
                rrsigRecord(comZSK, "com", comPrivateZSK, algorithm, example)));
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertTrue(result.isAuthenticData());
        checkCorrectExampleMessage(result.synthesizedResponse);
    }

    @Test
    public void testAllRrsigsInvalid() throws IOException {
        Record<A> example = record("example.com", a("1.1.1.2"));
        DnssecClient client = constructDnssecClientWithComZone(Arrays.asList(
                example,
                invalidComZskRrsig(example),
                rrsigRecord(ROGUE_KEY, "com", ROGUE_PRIVATE_KEY, algorithm, example)));
        assertThrows(DnssecValidationFailedException.class, () ->
            client.query("example.com", Record.TYPE.A)
        );
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testDnskeyRrsetSignedByDelegatedAndRogueKey() throws IOException {
        DnssecClient client = constructDnssecClient();
        Record<DNSKEY> comKskRecord = record("com", comKSK);
        Record<DNSKEY> comZskRecord = record("com", comZSK);
        Record<DNSKEY> rogueKeyRecord = record("com", ROGUE_KEY);
        List<Record<? extends Data>> records = merge(
                sign(comZSK, "com", comPrivateZSK, algorithm,
                        record("example.com", a("1.1.1.2"))));
        records.addAll(Arrays.asList(
                comKskRecord,
                comZskRecord,
                rogueKeyRecord,
                rrsigRecord(ROGUE_KEY, "com", ROGUE_PRIVATE_KEY, algorithm, comKskRecord, comZskRecord, rogueKeyRecord),
                rrsigRecord(comKSK, "com", comPrivateKSK, algorithm, comKskRecord, comZskRecord, rogueKeyRecord)));
        applyZones(client,
                signedRootZoneDelegatingCom(),
                zone("com", "ns.com", "1.1.1.1", records)
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertTrue(result.isAuthenticData());
        checkCorrectExampleMessage(result.synthesizedResponse);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testDnskeyRrsetSignedOnlyByKeyWithoutDelegation() throws IOException {
        DnssecClient client = constructDnssecClient();
        // The DNSKEY RRset contains comKSK, which the DS RR at the parent refers to. But the RRset is only signed by a
        // key that has no delegation, hence there is no chain of trust to the RRset.
        applyZones(client,
                signedRootZoneDelegatingCom(),
                zone("com", "ns.com", "1.1.1.1", merge(
                        sign(ROGUE_KEY, "com", ROGUE_PRIVATE_KEY, algorithm,
                                record("com", comKSK),
                                record("com", comZSK),
                                record("com", ROGUE_KEY)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                ))
        );
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertFalse(result.isAuthenticData());
    }

    @SuppressWarnings("unchecked")
    private static DnssecClient constructDnssecClientWithComDsRrSet(DS... comDsRrs) {
        DnssecClient client = constructDnssecClient();
        List<Record<? extends Data>> comDsRecords = new ArrayList<>(comDsRrs.length);
        for (DS ds : comDsRrs) {
            comDsRecords.add(record("com", ds));
        }
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                comDsRecords.toArray(new Record<?>[0])),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        return client;
    }

    @Test
    public void testUnknownDelegationDigestTypeAlongsideValidDs() throws IOException {
        DnssecClient client = constructDnssecClientWithComDsRrSet(
                ds(comKSK.getKeyTag(), algorithm, (byte) 213, new byte[0]),
                ds("com", DigestAlgorithm.SHA256, comKSK));
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertTrue(result.isAuthenticData());
        checkCorrectExampleMessage(result.synthesizedResponse);
    }

    @Test
    public void testDsKeyTagCollision() throws IOException {
        // The first DS RR has the same key tag and algorithm as comKSK, but refers to a different key.
        DnssecClient client = constructDnssecClientWithComDsRrSet(
                ds(comKSK.getKeyTag(), algorithm, DigestAlgorithm.SHA256,
                        calculateDsDigest(DnsName.from("com"), DigestAlgorithm.SHA256, comZSK)),
                ds("com", DigestAlgorithm.SHA256, comKSK));
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertTrue(result.isAuthenticData());
        checkCorrectExampleMessage(result.synthesizedResponse);
    }

    @Test
    public void testDsAlgorithmMismatch() throws IOException {
        DnssecClient client = constructDnssecClientWithComDsRrSet(
                ds(comKSK.getKeyTag(), SignatureAlgorithm.RSASHA1, DigestAlgorithm.SHA256,
                        calculateDsDigest(DnsName.from("com"), DigestAlgorithm.SHA256, comKSK)));
        DnssecQueryResult result = client.queryDnssec("example.com", Record.TYPE.A);
        assertFalse(result.isAuthenticData());
    }

    @Test
    public void testSha1DsIgnoredIfSha256DsPresent() {
        // The SHA-1 DS RR is valid, but the SHA-256 one is not. Since SHA-1 DS RRs have to be ignored if there is a
        // SHA-256 DS RR, the validation must fail.
        DnssecClient client = constructDnssecClientWithComDsRrSet(
                ds("com", DigestAlgorithm.SHA1, comKSK),
                ds(comKSK.getKeyTag(), algorithm, DigestAlgorithm.SHA256,
                        calculateDsDigest(DnsName.from("com"), DigestAlgorithm.SHA256, comZSK)));
        assertThrows(DnssecValidationFailedException.class, () ->
            client.queryDnssec("example.com", Record.TYPE.A)
        );
    }

    @SuppressWarnings("unchecked")
    private static DnssecQueryResult queryWithRootSecureEntryPoints(DNSKEY... rootSeps) throws IOException {
        DnssecClient client = constructDnssecClient();
        client.clearSecureEntryPoints();
        for (DNSKEY rootSep : rootSeps) {
            client.addSecureEntryPoint(DnsName.ROOT, rootSep.getKey());
        }
        applyZones(client,
                signedRootZoneDelegatingCom(),
                signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        return client.queryDnssec("example.com", Record.TYPE.A);
    }

    @Test
    public void testMultipleRootSecureEntryPoints() throws IOException {
        DnssecQueryResult result = queryWithRootSecureEntryPoints(ROGUE_KEY, rootKSK);
        assertTrue(result.isAuthenticData());
        checkCorrectExampleMessage(result.synthesizedResponse);
    }

    @Test
    public void testRootSecureEntryPointDoesNotSignDnskeyRrSet() throws IOException {
        DnssecQueryResult result = queryWithRootSecureEntryPoints(ROGUE_KEY);
        assertFalse(result.isAuthenticData());
        assertTrue(result.getUnverifiedReasons().iterator().next() instanceof DnssecUnverifiedReason.ConflictsWithSep);
    }
}
