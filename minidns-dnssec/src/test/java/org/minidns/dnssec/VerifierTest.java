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

import org.minidns.constants.DnssecConstants.SignatureAlgorithm;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsname.DnsName;
import org.minidns.dnssec.algorithms.JavaSecDigestCalculator;
import org.minidns.record.DNSKEY;
import org.minidns.record.Data;
import org.minidns.record.NSEC;
import org.minidns.record.NSEC3;
import org.minidns.record.RRSIG;
import org.minidns.record.Record;
import org.minidns.record.Record.TYPE;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.minidns.DnsWorld.a;
import static org.minidns.DnsWorld.dnskey;
import static org.minidns.DnsWorld.nsec;
import static org.minidns.DnsWorld.nsec3;
import static org.minidns.DnsWorld.record;
import static org.minidns.DnsWorld.rrsig;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class VerifierTest {

    @Test
    public void testNsecMatches() {
        assertTrue(Verifier.nsecMatches("example.com", "com", "com"));
        assertTrue(Verifier.nsecMatches("example.com", "e.com", "f.com"));
        assertTrue(Verifier.nsecMatches("example.com", "be", "de"));
        assertTrue(Verifier.nsecMatches("nsec.example.com", "example.com", "www.example.com"));
        assertFalse(Verifier.nsecMatches("example.com", "a.com", "example.com"));
        assertFalse(Verifier.nsecMatches("example.com", "example1.com", "example2.com"));
        assertFalse(Verifier.nsecMatches("example.com", "test.com", "xxx.com"));
        assertFalse(Verifier.nsecMatches("example.com", "xxx.com", "test.com"));
        assertFalse(Verifier.nsecMatches("example.com", "aaa.com", "bbb.com"));
        assertFalse(Verifier.nsecMatches("www.example.com", "example2.com", "example3.com"));
        assertFalse(Verifier.nsecMatches("test.nsec.example.com", "nsec.example.com", "a.nsec.example.com"));
        assertFalse(Verifier.nsecMatches("test.nsec.example.com", "test.nsec.example.com", "a.example.com"));
        assertFalse(Verifier.nsecMatches("www.example.com", "example.com", "nsec.example.com"));
        assertFalse(Verifier.nsecMatches("example.com", "nsec.example.com", "www.example.com"));
    }

    /**
     * Real-world ECDSAP256SHA256 signature of the cloudflare.com A RRset, whose r value starts with a zero byte that is
     * not required in the ASN.1 DER encoding. See <a href="https://github.com/MiniDNS/minidns/issues/151">MiniDNS issue
     * #151</a>.
     *
     * @throws IOException if an IO error occurs.
     */
    @Test
    public void testVerifyEcdsaSignatureWithRedundantLeadingZeroInR() throws IOException {
        // cloudflare.com. 300 IN RRSIG A 13 2 300 20261019104647 20261017084647 34505 cloudflare.com. ADQuxs4...
        byte[] signature = Base64.getDecoder().decode(
                "ADQuxs4tCvV2mv5ATNUeiOU1q7N0yw0/UEAlTkrWIxPLGFOW3ro/vKtEGd3XVOKdh/HCltXczWV1U3MfXHXy/g==");
        // Ensure that r has a redundant leading zero byte.
        assertEquals(0, signature[0]);
        assertEquals(0, signature[1] & 0x80);

        assertCloudflareARecordsSignatureValid(signature, "2026-10-19T10:46:47Z", "2026-10-17T08:46:47Z");
    }

    /**
     * Real-world ECDSAP256SHA256 signature of the cloudflare.com A RRset, whose s value starts with a zero byte that is
     * not required in the ASN.1 DER encoding. See <a href="https://github.com/MiniDNS/minidns/issues/151">MiniDNS issue
     * #151</a>.
     *
     * @throws IOException if an IO error occurs.
     */
    @Test
    public void testVerifyEcdsaSignatureWithRedundantLeadingZeroInS() throws IOException {
        // cloudflare.com. 300 IN RRSIG A 13 2 300 20261019104701 20261017084701 34505 cloudflare.com. v3HSuyG...
        byte[] signature = Base64.getDecoder().decode(
                "v3HSuyGY5TYEZyDkeC+61yNreYCHCscvP8umyk+9CR4ANmInlS2yyvTu2Yr8IDqHgYygEHUTvln8xgMqAoa69Q==");
        // Ensure that s has a redundant leading zero byte.
        assertEquals(0, signature[32]);
        assertEquals(0, signature[33] & 0x80);

        assertCloudflareARecordsSignatureValid(signature, "2026-10-19T10:47:01Z", "2026-10-17T08:47:01Z");
    }

    private static void assertCloudflareARecordsSignatureValid(byte[] signature, String signatureExpiration,
            String signatureInception) throws IOException {
        // cloudflare.com. 3600 IN DNSKEY 256 3 13 oJMRESz5...
        DNSKEY zsk = dnskey(DNSKEY.FLAG_ZONE, SignatureAlgorithm.ECDSAP256SHA256, Base64.getDecoder().decode(
                "oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA=="));
        assertEquals(34505, zsk.getKeyTag());

        List<Record<? extends Data>> records = new ArrayList<>();
        records.add(record("cloudflare.com", 300, a("104.16.132.229")));
        records.add(record("cloudflare.com", 300, a("104.16.133.229")));

        RRSIG rrsig = rrsig(TYPE.A, SignatureAlgorithm.ECDSAP256SHA256, 2, 300,
                Date.from(Instant.parse(signatureExpiration)), Date.from(Instant.parse(signatureInception)),
                zsk.getKeyTag(), "cloudflare.com", signature);

        assertNull(Verifier.verify(records, rrsig, zsk));
    }

    @Test
    public void testVerifyNsec() {
        Record<NSEC> nsecRecord = record("example.com", nsec("www.example.com", TYPE.A, TYPE.NS, TYPE.SOA, TYPE.TXT, TYPE.AAAA, TYPE.RRSIG, TYPE.NSEC, TYPE.DNSKEY)).as(NSEC.class);
        assertNull(Verifier.verifyNsec(nsecRecord, new Question("nsec.example.com", TYPE.A)));
        assertNull(Verifier.verifyNsec(nsecRecord, new Question("example.com", TYPE.PTR)));
        assertNotNull(Verifier.verifyNsec(nsecRecord, new Question("www.example.com", TYPE.A)));
        assertNotNull(Verifier.verifyNsec(nsecRecord, new Question("example.com", TYPE.NS)));
    }

    @Test
    public void testVerifyNsec3() {
        byte[] bytes = new byte[] {0x3f, (byte) 0xb1, (byte) 0xd0, (byte) 0xaa, 0x27, (byte) 0xe2, 0x5f, (byte) 0xda, 0x40, 0x75, (byte) 0x92, (byte) 0x95, 0x5a, 0x1c, 0x7f, (byte) 0x98, (byte) 0xdb, 0x5b, 0x79, (byte) 0x91};
        Record<NSEC3> nsec3Record = record("7UO4LIHALHHLNGLJAFT7TBIQ6H1SL1CN.net", nsec3((byte) 1, (byte) 1, 0, new byte[0], bytes, TYPE.NS, TYPE.SOA, TYPE.RRSIG, TYPE.DNSKEY, TYPE.NSEC3PARAM)).as(NSEC3.class);
        DnsName zone = DnsName.from("net");
        assertNull(Verifier.verifyNsec3(zone, nsec3Record, new Question("x.net", TYPE.A)));
        assertNotNull(Verifier.verifyNsec3(zone, nsec3Record, new Question("example.net", TYPE.A)));
    }

    @Test
    public void testNsec3hash() throws Exception {
        JavaSecDigestCalculator digestCalculator = new JavaSecDigestCalculator("SHA-1");
        assertEquals("6e8777855bcd60d7b45fc51893776dde75bf6cd4", new BigInteger(1, Verifier.nsec3hash(digestCalculator, new byte[] {42}, new byte[] {88}, 5)).toString(16));
    }
}
