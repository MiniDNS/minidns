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
import org.minidns.record.Record.CLASS;
import org.minidns.record.Record.TYPE;
import org.minidns.record.UNKNOWN;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
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

    /**
     * The NSEC3 RR of the .xxx zone apex has the private use type 65534 in its type bitmap, which is unknown to
     * MiniDNS. Verifying the RRSIGs covering it requires that the type bitmap is not altered when the RR is parsed.
     *
     * @see <a href="https://github.com/MiniDNS/minidns/issues/121">MiniDNS issue #121</a>
     */
    @Test
    public void testVerifyNsec3WithUnknownTypeInTypeBitmap() throws IOException {
        // d3af3knn4crq0h4h8ppmf7nal1s271gb.xxx. NSEC3 1 1 0 - D3OBB7D5V2H77C2BFUM7FQBGJ7BV4R1J NS SOA RRSIG DNSKEY NSEC3PARAM TYPE65534
        byte[] nsec3Bytes = hexToBytes("01010000001468f0b59da5f8a273b04b7fac77e97099d7f26c33000722000000000290ff200000000000000000000000"
                + "000000000000000000000000000000000000000002");
        NSEC3 nsec3 = NSEC3.parse(new DataInputStream(new ByteArrayInputStream(nsec3Bytes)), nsec3Bytes.length);
        List<Record<? extends Data>> records = Collections.<Record<? extends Data>>singletonList(
                new Record<>(DnsName.from("d3af3knn4crq0h4h8ppmf7nal1s271gb.xxx"), TYPE.NSEC3, CLASS.IN.getValue(), 900, nsec3));

        // RSASHA256 RRSIG and the corresponding ZSK of .xxx with key tag 30300.
        assertVerifies(records,
                "00320802000003846ae247986acfcf65765c03787878001f12508fecb855c3d1ea0e785da6970b29e34ae8d058c09a0a"
                + "81199a7aace2d4d6fcb8382bd24b947f01ff7ffc751b40f70593124c00ea4fda3d14923a8e300ad95baf5504a70b2724"
                + "0415d4fc2df2a90c31a2f813161bb324d36013d09fe814b69bdf4cdef0ef294854fececa79c82dbd5c2a5e4b7d6296d4"
                + "9a1a7ac201d9930d9371c42cfa3e0f97106924e9edf359a51727deb627c0b6dcb2caa2864da657",
                "01000308030100019f99964778f040901ae60cee36c2e66783173afa808df6177f92d5f6f7188f1df6b7b4e785326007"
                + "03dceb12cee59342096c327d319b5cd285311fecf08f31a470e834ffefaa1630d838d9c6bf3bb299d100242c52e18488"
                + "4f0f125aff94835aac3c32ba6cea5b81b1e5b33def69cb2cfa30026b3bfd9022cf641e15bdb02f83e008544ffa2f4a94"
                + "a677fa7fc2d4c1e81a5e2468da60d4e8ee4b9a2924f59187");

        // ECDSAP256SHA256 RRSIG and the corresponding ZSK of .xxx with key tag 62266.
        assertVerifies(records,
                "00320d02000003846ae247986acfcf65f33a0378787800f32051347f26e6ab245a00ed984096447f0e8b479193878842"
                + "0d77f2e7d215732e42dfcadd9ad3cf6925dd204cc8d9cb49b5f08e8bd07cb876004974566b9bec",
                "0100030d934410d29142983cb2f78a737522eef4ed8c4775ed2feee43f7d6e5cc47fd9e3b0eef24be666ba03ad2edb66"
                + "ff4958143235b6d610688b968bc11d39381e9904");
    }

    private static RRSIG assertVerifies(List<Record<? extends Data>> records, String rrsigHex, String dnskeyHex) throws IOException {
        byte[] rrsigBytes = hexToBytes(rrsigHex);
        RRSIG rrsig = RRSIG.parse(new DataInputStream(new ByteArrayInputStream(rrsigBytes)), rrsigBytes, rrsigBytes.length);
        byte[] dnskeyBytes = hexToBytes(dnskeyHex);
        DNSKEY dnskey = DNSKEY.parse(new DataInputStream(new ByteArrayInputStream(dnskeyBytes)), dnskeyBytes.length);
        assertEquals(rrsig.keyTag, dnskey.getKeyTag());

        assertNull(Verifier.verify(records, rrsig, dnskey));
        return rrsig;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    /**
     * The .xxx zone apex holds a RRset of the private use type 65534, which is unknown to MiniDNS. Verifying the
     * RRSIGs covering it requires that the type value is not lost, neither in the RRs nor in the RRSIGs.
     */
    @Test
    public void testVerifyRrsetWithUnknownType() throws IOException {
        String[] rdatas = new String[] {
                "07a43f0001",
                "0795a60001",
                "076ca40001",
                "0df33a0001",
                "076e560001",
                "0d7db10001",
                "08990f0001",
                "08dcae0001",
        };
        List<Record<? extends Data>> records = new ArrayList<>(rdatas.length);
        for (String rdata : rdatas) {
            byte[] rdataBytes = hexToBytes(rdata);
            UNKNOWN payload = UNKNOWN.parse(new DataInputStream(new ByteArrayInputStream(rdataBytes)), rdataBytes.length, 65534);
            records.add(new Record<>(DnsName.from("xxx"), TYPE.UNKNOWN, CLASS.IN.getValue(), 0, payload));
        }

        // RSASHA256 RRSIG and the corresponding ZSK of .xxx with key tag 30300.
        RRSIG rrsig = assertVerifies(records,
                "fffe0801000000006ae3e00c6ad165db765c03787878000991df71a9f97036b52143d0fdb572bafd60c4263ec1454d13"
                + "7d1cb75366204c2ad70659c96606ad032f8bb2b7fd154fb2536017bfdb320aad57e8a0c361b35a356cf4b1d634aee6ae"
                + "946ec781e336d1b0b1f3b664807aba41c521bfad3d9da4fe6deb823b0aaf2e813862bca4324dcd16df71671326b48112"
                + "891196379f4f9424a5a5a1de5c2faac4ab30fd29c645fc70ea52b2dc5ecf718651115812b34d52",
                "01000308030100019f99964778f040901ae60cee36c2e66783173afa808df6177f92d5f6f7188f1df6b7b4e785326007"
                + "03dceb12cee59342096c327d319b5cd285311fecf08f31a470e834ffefaa1630d838d9c6bf3bb299d100242c52e18488"
                + "4f0f125aff94835aac3c32ba6cea5b81b1e5b33def69cb2cfa30026b3bfd9022cf641e15bdb02f83e008544ffa2f4a94"
                + "a677fa7fc2d4c1e81a5e2468da60d4e8ee4b9a2924f59187");
        assertEquals(65534, rrsig.typeCoveredValue);

        // ECDSAP256SHA256 RRSIG and the corresponding ZSK of .xxx with key tag 62266.
        assertVerifies(records,
                "fffe0d01000000006ae3e00c6ad165dbf33a037878780037d4a3e5e89fea30695f9ffdffae168d04d92a8022aee585f1"
                + "b6ec58a25a8c9b25b03d78e20450503eba9e30fb9681dda58e155acd6b182a1cb873e21c8b2f0a",
                "0100030d934410d29142983cb2f78a737522eef4ed8c4775ed2feee43f7d6e5cc47fd9e3b0eef24be666ba03ad2edb66"
                + "ff4958143235b6d610688b968bc11d39381e9904");
    }
}
