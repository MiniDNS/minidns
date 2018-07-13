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
package org.minidns.dnssec;

import org.minidns.DnsWorld;
import org.minidns.cache.LruCache;
import org.minidns.constants.DnssecConstants.DigestAlgorithm;
import org.minidns.constants.DnssecConstants.SignatureAlgorithm;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsname.DnsName;
import org.minidns.dnssec.DnssecValidationFailedException.AuthorityDoesNotContainSoa;
import org.minidns.record.A;
import org.minidns.record.DNSKEY;
import org.minidns.record.Data;
import org.minidns.record.RRSIG;
import org.minidns.record.Record;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.util.Date;
import java.util.List;

import static org.minidns.DnsWorld.a;
import static org.minidns.DnsWorld.applyZones;
import static org.minidns.DnsWorld.dnskey;
import static org.minidns.DnsWorld.ns;
import static org.minidns.DnsWorld.nsec;
import static org.minidns.DnsWorld.record;
import static org.minidns.DnsWorld.rootZone;
import static org.minidns.DnsWorld.rrsig;
import static org.minidns.DnsWorld.soa;
import static org.minidns.DnsWorld.zone;
import static org.minidns.dnssec.DnssecWorld.dlv;
import static org.minidns.dnssec.DnssecWorld.ds;
import static org.minidns.dnssec.DnssecWorld.generatePrivateKey;
import static org.minidns.dnssec.DnssecWorld.publicKey;
import static org.minidns.dnssec.DnssecWorld.rrsigRecord;
import static org.minidns.dnssec.DnssecWorld.sign;
import static org.minidns.dnssec.DnssecWorld.signedRootZone;
import static org.minidns.dnssec.DnssecWorld.signedZone;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
    private DnssecClient client;

    @BeforeClass
    public static void generateKeys() {
        rootPrivateKSK = generatePrivateKey(algorithm, 2048);
        rootKSK = dnskey(DNSKEY.FLAG_ZONE | DNSKEY.FLAG_SECURE_ENTRY_POINT, algorithm, publicKey(algorithm, rootPrivateKSK));
        rootPrivateZSK = generatePrivateKey(algorithm, 1024);
        rootZSK = dnskey(DNSKEY.FLAG_ZONE, algorithm, publicKey(algorithm, rootPrivateZSK));
        comPrivateKSK = generatePrivateKey(algorithm, 2048);
        comKSK = dnskey(DNSKEY.FLAG_ZONE | DNSKEY.FLAG_SECURE_ENTRY_POINT, algorithm, publicKey(algorithm, comPrivateKSK));
        comPrivateZSK = generatePrivateKey(algorithm, 1024);
        comZSK = dnskey(DNSKEY.FLAG_ZONE, algorithm, publicKey(algorithm, comPrivateZSK));
    }

    @Before
    public void setUp() throws Exception {
        client = new DnssecClient(new LruCache(0));
        client.addSecureEntryPoint(DnsName.ROOT, rootKSK.getKey());
    }

    void checkCorrectExampleMessage(DnsMessage message) {
        List<Record<? extends Data>> answers = message.answerSection;
        assertEquals(1, answers.size());
        assertEquals(Record.TYPE.A, answers.get(0).type);
        assertArrayEquals(new byte[]{1, 1, 1, 2}, ((A) answers.get(0).payloadData).getIp());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testBasicValid() throws IOException {
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
    @Test(expected = AuthorityDoesNotContainSoa.class)
    public void testMissingDelegation() throws IOException {
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
        client.queryDnssec("example.com", Record.TYPE.A);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUnsignedRoot() throws IOException {
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
    @Test(expected = DnssecValidationFailedException.class)
    public void testInvalidDNSKEY() throws IOException {
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
        client.query("example.com", Record.TYPE.A);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = DnssecValidationFailedException.class)
    public void testNoDNSKEY() throws IOException {
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
        client.query("example.com", Record.TYPE.A);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = DnssecValidationFailedException.class)
    public void testInvalidRRSIG() throws IOException, NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
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
        client.query("example.com", Record.TYPE.A);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUnknownAlgorithm() throws IOException {
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
    @Test(expected = DnssecValidationFailedException.class)
    public void testInvalidDelegation() throws IOException {
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
        client.query("example.com", Record.TYPE.A);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUnknownDelegationDigestType() throws IOException {
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

    @SuppressWarnings("unchecked")
    @Test
    public void testSignatureOutOfDate() throws IOException {
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

    @SuppressWarnings("unchecked")
    @Test
    public void testSignatureInFuture() throws IOException {
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
        world.addPreparedResponse(new DnssecWorld.AddressedNsecResponse(InetAddress.getByAddress("ns.com", new byte[]{1, 1, 1, 1}), nsecMessage.build()));
        DnssecQueryResult result = client.queryDnssec("nsec.example.com", Record.TYPE.A);
        // TODO: The setSripSignatureRecords() call could probably be removed. It does not appear to server any purpose here.
        client.setStripSignatureRecords(false);
        DnsMessage message = result.synthesizedResponse;
        assertEquals(0, message.answerSection.size());
        assertTrue(message.authenticData);
    }

    @Ignore
    @SuppressWarnings("unchecked")
    @Test
    public void testValidDLV() throws IOException {
        PrivateKey dlvPrivateKSK = generatePrivateKey(algorithm, 2048);
        DNSKEY dlvKSK = dnskey(DNSKEY.FLAG_ZONE | DNSKEY.FLAG_SECURE_ENTRY_POINT, algorithm, publicKey(algorithm, dlvPrivateKSK));
        PrivateKey dlvPrivateZSK = generatePrivateKey(algorithm, 1024);
        DNSKEY dlvZSK = dnskey(DNSKEY.FLAG_ZONE, algorithm, publicKey(algorithm, dlvPrivateZSK));
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("dlv", ds("dlv", digestType, dlvKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("dlv", ns("ns.com"))),
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
                ), signedZone("dlv", "ns.com", "1.1.1.1",
                        sign(dlvKSK, "dlv", dlvPrivateKSK, algorithm,
                                record("dlv", dlvKSK),
                                record("dlv", dlvZSK)),
                        sign(dlvZSK, "dlv", dlvPrivateZSK, algorithm,
                                record("com.dlv", dlv("com", digestType, comKSK)))
                )
        );
        // TODO: Add nsec response for [Q: com. IN  DS] NX_DOMAIN
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
}
