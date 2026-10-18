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
package org.minidns.dane;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.minidns.DnsWorld.a;
import static org.minidns.DnsWorld.applyZones;
import static org.minidns.DnsWorld.cname;
import static org.minidns.DnsWorld.ns;
import static org.minidns.DnsWorld.record;
import static org.minidns.dnssec.DnssecWorld.ds;
import static org.minidns.dnssec.DnssecWorld.merge;
import static org.minidns.dnssec.DnssecWorld.selfSignDnskeyRrSet;
import static org.minidns.dnssec.DnssecWorld.sign;
import static org.minidns.dnssec.DnssecWorld.signedRootZone;
import static org.minidns.dnssec.DnssecWorld.signedZone;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.minidns.DnsWorld;
import org.minidns.DnsWorld.AddressedAnswerResponse;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnssec.DnssecClient;
import org.minidns.dnssec.DnssecClientTest;
import org.minidns.dnssec.DnssecWorld.SignedRRSet;
import org.minidns.record.Record;
import org.minidns.record.Record.TYPE;
import org.minidns.record.TLSA;

public class DaneVerifierTest {

    private static final String HOST = "www.example.com";
    private static final int PORT = 443;
    private static final String TLSA_NAME = "_" + PORT + "._tcp." + HOST;
    private static final String TLSA_TARGET_NAME = "_" + PORT + "._tcp.tlsa.example.com";

    // Self-signed certificate for CN=example.com, generated with
    // openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 36500 -subj "/CN=example.com"
    private static final String CERTIFICATE_PEM =
                    "-----BEGIN CERTIFICATE-----\n"
                  + "MIIBgzCCASmgAwIBAgIUef/DTx5IqoAyFJbBcVwWXbTJ2aEwCgYIKoZIzj0EAwIw\n"
                  + "FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wIBcNMjYxMDE4MTE1NDA1WhgPMjEyNjA5\n"
                  + "MjQxMTU0MDVaMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYI\n"
                  + "KoZIzj0DAQcDQgAEfKikeBlJcUsTldNH6XcMOTXNfXlSSNk4UJOn4nMQvLXsx62J\n"
                  + "0Q8KIjQ8q5F+Q1Z4fQufT0CSkgPZeoEiRAAV3KNTMFEwHQYDVR0OBBYEFPKwrcez\n"
                  + "5YOWIXWpWEAAWC7O8F84MB8GA1UdIwQYMBaAFPKwrcez5YOWIXWpWEAAWC7O8F84\n"
                  + "MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgQihJZmUlbLcsFbFc\n"
                  + "/u8eFQpD0zcujE9o+yjE1xuVIeYCIQDsxfPim9GFUwhz8caH8t6BaGsI2ctf85B8\n"
                  + "SFe8l2pDYA==\n"
                  + "-----END CERTIFICATE-----\n";

    private static final X509Certificate[] CHAIN;
    private static final byte[] SPKI_SHA256;

    static {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(
                    new ByteArrayInputStream(CERTIFICATE_PEM.getBytes(StandardCharsets.US_ASCII)));
            CHAIN = new X509Certificate[] { certificate };
            SPKI_SHA256 = MessageDigest.getInstance("SHA-256").digest(certificate.getPublicKey().getEncoded());
        } catch (CertificateException | NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    private static TLSA tlsa(int certUsage, int selector, int matchingType, byte[] certificateAssociation) {
        byte[] bytes = new byte[3 + certificateAssociation.length];
        bytes[0] = (byte) certUsage;
        bytes[1] = (byte) selector;
        bytes[2] = (byte) matchingType;
        System.arraycopy(certificateAssociation, 0, bytes, 3, certificateAssociation.length);
        try {
            return TLSA.parse(new DataInputStream(new ByteArrayInputStream(bytes)), bytes.length);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    private static TLSA matching(int certUsage) {
        return tlsa(certUsage, 1, 1, SPKI_SHA256);
    }

    private static TLSA mismatching(int certUsage) {
        byte[] wrong = SPKI_SHA256.clone();
        wrong[0] = (byte) ~wrong[0];
        return tlsa(certUsage, 1, 1, wrong);
    }

    private static InetAddress comNameserver() throws IOException {
        return InetAddress.getByAddress("ns.com", new byte[] {1, 1, 1, 1});
    }

    private static DnsWorld applyComZone(DnssecClient client, SignedRRSet... comRrSets) {
        SignedRRSet[] rrSets = new SignedRRSet[comRrSets.length + 1];
        rrSets[0] = selfSignDnskeyRrSet("com");
        System.arraycopy(comRrSets, 0, rrSets, 1, comRrSets.length);
        return applyZones(client,
                signedRootZone(
                        selfSignDnskeyRrSet(""),
                        sign("",
                                ds("com")),
                        sign("",
                                record("com", ns("ns.com"))),
                        sign("",
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1", rrSets)
        );
    }

    private static DnssecClient clientWithTlsaRecords(TLSA... tlsas) {
        @SuppressWarnings({"unchecked", "rawtypes"})
        Record<TLSA>[] tlsaRecords = new Record[tlsas.length];
        for (int i = 0; i < tlsas.length; i++) {
            tlsaRecords[i] = record(TLSA_NAME, tlsas[i]);
        }

        DnssecClient client = DnssecClientTest.constructDnssecClient();
        applyComZone(client,
                sign("com",
                        tlsaRecords)
        );
        return client;
    }

    // Make the nameserver of the 'com' zone answer the TLSA query for TLSA_NAME with the given RRsets, like a
    // resolver following CNAMEs would do.
    private static void addTlsaResponse(DnsWorld dnsWorld, SignedRRSet... rrSets) throws IOException {
        DnsMessage request = DnsMessage.builder()
                .setQuestion(new Question(TLSA_NAME, TYPE.TLSA))
                .build();
        DnsMessage response = DnsMessage.builder()
                .setAnswers(merge(rrSets))
                .setAuthoritativeAnswer(true)
                .build();
        dnsWorld.addPreparedResponse(new AddressedAnswerResponse(comNameserver(), request, response));
    }

    private static DaneVerificationResult daneVerify(DnssecClient client) throws CertificateException {
        return new DaneVerifier(client).daneVerify(CHAIN, HOST, PORT);
    }

    private static boolean verifyCertificateChain(DnssecClient client) throws CertificateException {
        return new DaneVerifier(client).verifyCertificateChain(CHAIN, HOST, PORT);
    }

    @Test
    public void testDaneEeMatch() throws CertificateException {
        DnssecClient client = clientWithTlsaRecords(matching(3));
        assertEquals(DaneVerificationResult.verified, daneVerify(client));
        assertTrue(verifyCertificateChain(client));
    }

    @Test
    public void testPkixEeMatch() throws CertificateException {
        DnssecClient client = clientWithTlsaRecords(matching(1));
        assertEquals(DaneVerificationResult.matchedPkixRequired, daneVerify(client));
        assertFalse(verifyCertificateChain(client));
    }

    @Test
    public void testPkixEeMatchAndDaneEeMatch() throws CertificateException {
        DnssecClient client = clientWithTlsaRecords(matching(1), matching(3));
        assertEquals(DaneVerificationResult.verified, daneVerify(client));
    }

    @Test
    public void testPkixEeMatchAndDaneEeMismatch() throws CertificateException {
        DnssecClient client = clientWithTlsaRecords(matching(1), mismatching(3));
        assertEquals(DaneVerificationResult.matchedPkixRequired, daneVerify(client));
        assertFalse(verifyCertificateChain(client));
    }

    @Test
    public void testDaneEeMismatchAndPkixEeMatch() throws CertificateException {
        DnssecClient client = clientWithTlsaRecords(mismatching(3), matching(1));
        assertEquals(DaneVerificationResult.matchedPkixRequired, daneVerify(client));
    }

    @Test
    public void testMismatch() {
        DnssecClient client = clientWithTlsaRecords(mismatching(1), mismatching(3));
        assertThrows(DaneCertificateException.MultipleCertificateMismatchExceptions.class, () -> daneVerify(client));
        assertThrows(DaneCertificateException.MultipleCertificateMismatchExceptions.class, () -> verifyCertificateChain(client));
    }

    @Test
    public void testOnlyUnsupportedCertUsage() throws CertificateException {
        // DANE-TA (2) is not supported by DaneVerifier.
        DnssecClient client = clientWithTlsaRecords(matching(2));
        assertEquals(DaneVerificationResult.noUsableTlsaRecords, daneVerify(client));
        assertFalse(verifyCertificateChain(client));
    }

    @Test
    public void testNotAuthenticated() throws CertificateException {
        DnssecClient client = clientWithTlsaRecords(matching(3));
        client.clearSecureEntryPoints();
        assertEquals(DaneVerificationResult.notAuthenticated, daneVerify(client));
        assertFalse(verifyCertificateChain(client));
    }

    @Test
    public void testTlsaViaCname() throws IOException, CertificateException {
        DnssecClient client = DnssecClientTest.constructDnssecClient();
        SignedRRSet cnameRrSet = sign("com", record(TLSA_NAME, cname(TLSA_TARGET_NAME)));
        SignedRRSet tlsaRrSet = sign("com", record(TLSA_TARGET_NAME, matching(3)));
        DnsWorld dnsWorld = applyComZone(client, cnameRrSet, tlsaRrSet);
        addTlsaResponse(dnsWorld, cnameRrSet, tlsaRrSet);
        assertEquals(DaneVerificationResult.verified, daneVerify(client));
    }

    @Test
    public void testTlsaViaCnameTargetNotInResponse() throws IOException, CertificateException {
        DnssecClient client = DnssecClientTest.constructDnssecClient();
        SignedRRSet cnameRrSet = sign("com", record(TLSA_NAME, cname(TLSA_TARGET_NAME)));
        SignedRRSet tlsaRrSet = sign("com", record(TLSA_TARGET_NAME, matching(3)));
        DnsWorld dnsWorld = applyComZone(client, cnameRrSet, tlsaRrSet);
        // Only respond with the CNAME, the TLSA RRs of the target must be queried separately.
        addTlsaResponse(dnsWorld, cnameRrSet);
        assertEquals(DaneVerificationResult.verified, daneVerify(client));
    }

    @Test
    public void testTlsaViaCnameMismatch() throws IOException {
        DnssecClient client = DnssecClientTest.constructDnssecClient();
        SignedRRSet cnameRrSet = sign("com", record(TLSA_NAME, cname(TLSA_TARGET_NAME)));
        SignedRRSet tlsaRrSet = sign("com", record(TLSA_TARGET_NAME, mismatching(3)));
        DnsWorld dnsWorld = applyComZone(client, cnameRrSet, tlsaRrSet);
        addTlsaResponse(dnsWorld, cnameRrSet, tlsaRrSet);
        assertThrows(DaneCertificateException.MultipleCertificateMismatchExceptions.class, () -> daneVerify(client));
    }
}
