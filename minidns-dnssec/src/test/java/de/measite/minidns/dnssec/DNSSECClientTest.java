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
package de.measite.minidns.dnssec;

import de.measite.minidns.DNSMessage;
import de.measite.minidns.DNSSECConstants.DigestAlgorithm;
import de.measite.minidns.DNSSECConstants.SignatureAlgorithm;
import de.measite.minidns.DNSName;
import de.measite.minidns.DNSWorld;
import de.measite.minidns.Record;
import de.measite.minidns.cache.LRUCache;
import de.measite.minidns.record.A;
import de.measite.minidns.record.DNSKEY;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.RRSIG;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.util.Date;
import java.util.List;

import static de.measite.minidns.DNSWorld.a;
import static de.measite.minidns.DNSWorld.applyZones;
import static de.measite.minidns.DNSWorld.dnskey;
import static de.measite.minidns.DNSWorld.ns;
import static de.measite.minidns.DNSWorld.nsec;
import static de.measite.minidns.DNSWorld.record;
import static de.measite.minidns.DNSWorld.rootZone;
import static de.measite.minidns.DNSWorld.rrsig;
import static de.measite.minidns.DNSWorld.soa;
import static de.measite.minidns.DNSWorld.zone;
import static de.measite.minidns.dnssec.DNSSECWorld.dlv;
import static de.measite.minidns.dnssec.DNSSECWorld.ds;
import static de.measite.minidns.dnssec.DNSSECWorld.generatePrivateKey;
import static de.measite.minidns.dnssec.DNSSECWorld.publicKey;
import static de.measite.minidns.dnssec.DNSSECWorld.rrsigRecord;
import static de.measite.minidns.dnssec.DNSSECWorld.sign;
import static de.measite.minidns.dnssec.DNSSECWorld.signedRootZone;
import static de.measite.minidns.dnssec.DNSSECWorld.signedZone;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class DNSSECClientTest {
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
    private DNSSECClient client;

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
        client = new DNSSECClient(new LRUCache(0));
        client.addSecureEntryPoint(DNSName.EMPTY, rootKSK.getKey());
    }

    void checkCorrectExampleMessage(DNSMessage message) {
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
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertTrue(message.authenticData);
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
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertTrue(message.authenticData);
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
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertTrue(message.authenticData);
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test
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
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.authenticData);
        checkCorrectExampleMessage(message);
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
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.authenticData);
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
        DNSSECMessage message = client.queryDnssec("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.authenticData);
        checkCorrectExampleMessage(message);
        assertEquals(1, message.getUnverifiedReasons().size());
        assertTrue(message.getUnverifiedReasons().iterator().next() instanceof UnverifiedReason.NoRootSecureEntryPointReason);
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
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.authenticData);
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = DNSSECValidationFailedException.class)
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
    @Test(expected = DNSSECValidationFailedException.class)
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
    @Test(expected = DNSSECValidationFailedException.class)
    public void testInvalidRRSIG() throws IOException {
        Record<? extends Data> invalidRrSig = rrsigRecord(comZSK, "com", comPrivateZSK, algorithm, record("example.com", a("1.1.1.2")));
        byte[] signatureMod = ((RRSIG) invalidRrSig.payloadData).signature;
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
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.authenticData);
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = DNSSECValidationFailedException.class)
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
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.authenticData);
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
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.authenticData);
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
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.authenticData);
        checkCorrectExampleMessage(message);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testValidNSEC() throws Exception {
        DNSWorld world = applyZones(client,
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
        DNSMessage.Builder nsecMessage = DNSMessage.builder();
        List<Record<? extends Data>> records = DNSSECWorld.merge(
                                sign(comZSK, "com", comPrivateZSK, algorithm,
                                        record("example.com", nsec("www.example.com", Record.TYPE.A))),
                                sign(comZSK, "com", comPrivateZSK, algorithm,
                                        record("example.com", soa("sns.dns.icann.org", "noc.dns.icann.org", 2015081265, 7200, 3600, 1209600, 3600))));
        nsecMessage.setNameserverRecords(records);
        nsecMessage.setAuthoritativeAnswer(true);
        world.addPreparedResponse(new DNSSECWorld.AddressedNsecResponse(InetAddress.getByAddress("ns.com", new byte[]{1, 1, 1, 1}), nsecMessage.build()));
        DNSMessage message = client.query("nsec.example.com", Record.TYPE.A);
        client.setStripSignatureRecords(false);
        assertNotNull(message);
        assertEquals(0, message.answerSection.size());
        assertTrue(message.authenticData);
    }

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
        client.configureLookasideValidation(DNSName.from("dlv"));
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertTrue(message.authenticData);
        checkCorrectExampleMessage(message);
        client.disableLookasideValidation();
        message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.authenticData);
        checkCorrectExampleMessage(message);
    }
}
