/*
 * Copyright 2015 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.record;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.Base64;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.util.Date;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * These are some tests for all records.
 *
 * The tests main purpose is to test if the output of toByteArray() is parsed into it's original value.
 *
 * Additionally, toString() is tested to be RFC compliant.
 */
public class RecordsTest {
    @Test
    public void testARecord() throws Exception {
        A a = new A(new byte[]{127, 0, 0, 1});
        assertEquals("127.0.0.1", a.toString());
        Assert.assertEquals(TYPE.A, a.getType());
        byte[] ab = a.toByteArray();
        a = new A(new DataInputStream(new ByteArrayInputStream(ab)), ab, ab.length);
        assertArrayEquals(new byte[]{127, 0, 0, 1}, a.ip);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testARecordInvalidIp() throws Exception {
        new A(new byte[42]);
    }

    @Test
    public void testAAAARecord() throws Exception {
        AAAA aaaa = new AAAA(new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, (byte) 0x85, (byte) 0xa3, 0x08, (byte) 0xd3, 0x13, 0x19, (byte) 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44});
        // Note: there are multiple valid representations of the IPv6 address due to optional reductions.
        assertEquals("2001:db8:85a3:8d3:1319:8a2e:370:7344", aaaa.toString());
        Assert.assertEquals(TYPE.AAAA, aaaa.getType());
        byte[] aaaab  = aaaa.toByteArray();
        aaaa = new AAAA(new DataInputStream(new ByteArrayInputStream(aaaab)), aaaab, aaaab.length);
        assertArrayEquals(new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, (byte) 0x85, (byte) 0xa3, 0x08, (byte) 0xd3, 0x13, 0x19, (byte) 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44}, aaaa.ip);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAAAARecordInvalidIp() throws Exception {
        new AAAA(new byte[42]);
    }

    @Test
    public void testCnameRecord() throws Exception {
        CNAME cname = new CNAME("www.example.com");
        assertEquals("www.example.com.", cname.toString());
        assertEquals(TYPE.CNAME, cname.getType());
        byte[] cnameb = cname.toByteArray();
        cname = new CNAME(new DataInputStream(new ByteArrayInputStream(cnameb)), cnameb, cnameb.length);
        assertEquals("www.example.com", cname.name);
    }

    @Test
    public void testDlvRecord() throws Exception {
        DLV dlv = new DLV(42, (byte) 8, (byte) 2, new byte[]{0x13, 0x37});
        assertEquals("42 8 2 1337", dlv.toString());
        assertEquals(TYPE.DLV, dlv.getType());
        byte[] dlvb = dlv.toByteArray();
        dlv = new DLV(new DataInputStream(new ByteArrayInputStream(dlvb)), dlvb, dlvb.length);
        assertEquals(42, dlv.keyTag);
        assertEquals(8, dlv.algorithm);
        assertEquals(2, dlv.digestType);
        assertArrayEquals(new byte[]{0x13, 0x37}, dlv.digest);
    }

    @Test
    public void testDnskeyRecord() throws Exception {
        DNSKEY dnskey = new DNSKEY(DNSKEY.FLAG_ZONE, (byte) 3, (byte) 1, new byte[]{42});
        // TODO: Compare with real Base64 once done
        assertEquals("256 3 1 " + Base64.encodeToString(dnskey.key), dnskey.toString());
        assertEquals(TYPE.DNSKEY, dnskey.getType());
        byte[] dnskeyb = dnskey.toByteArray();
        dnskey = new DNSKEY(new DataInputStream(new ByteArrayInputStream(dnskeyb)), dnskeyb, dnskeyb.length);
        assertEquals(256, dnskey.flags);
        assertEquals(3, dnskey.protocol);
        assertEquals(1, dnskey.algorithm);
        assertArrayEquals(new byte[]{42}, dnskey.key);
    }

    @Test
    public void testDsRecord() throws Exception {
        DS ds = new DS(42, (byte) 8, (byte) 2, new byte[]{0x13, 0x37});
        assertEquals("42 8 2 1337", ds.toString());
        assertEquals(TYPE.DS, ds.getType());
        byte[] dsb = ds.toByteArray();
        ds = new DS(new DataInputStream(new ByteArrayInputStream(dsb)), dsb, dsb.length);
        assertEquals(42, ds.keyTag);
        assertEquals(8, ds.algorithm);
        assertEquals(2, ds.digestType);
        assertArrayEquals(new byte[]{0x13, 0x37}, ds.digest);
    }

    @Test
    public void testMxRecord() throws Exception {
        MX mx = new MX(10, "mx.example.com");
        assertEquals("10 mx.example.com.", mx.toString());
        assertEquals(TYPE.MX, mx.getType());
        byte[] mxb = mx.toByteArray();
        mx = new MX(new DataInputStream(new ByteArrayInputStream(mxb)), mxb, mxb.length);
        assertEquals(10, mx.priority);
        assertEquals("mx.example.com", mx.name);
    }

    @Test
    public void testNsecRecord() throws Exception {
        NSEC nsec = new NSEC("example.com", new TYPE[]{TYPE.A, TYPE.RRSIG, TYPE.DLV});
        assertEquals("example.com. A RRSIG DLV", nsec.toString());
        assertEquals(TYPE.NSEC, nsec.getType());
        byte[] nsecb = nsec.toByteArray();
        nsec = new NSEC(new DataInputStream(new ByteArrayInputStream(nsecb)), nsecb, nsecb.length);
        assertEquals("example.com", nsec.next);
        assertArrayEquals(new TYPE[]{TYPE.A, TYPE.RRSIG, TYPE.DLV}, nsec.types);

        assertEquals(0, NSEC.readTypeBitMap(NSEC.createTypeBitMap(new TYPE[0])).length);
    }

    @Test
    public void testNsec3Record() throws Exception {
        NSEC3 nsec3 = new NSEC3((byte) 1, (byte) 1, 1, new byte[]{0x13, 0x37}, new byte[]{0x42, 0x42, 0x42, 0x42, 0x42}, new TYPE[]{TYPE.A});
        assertEquals("1 1 1 1337 89144GI2 A", nsec3.toString());
        assertEquals(TYPE.NSEC3, nsec3.getType());
        byte[] nsec3b = nsec3.toByteArray();
        nsec3 = new NSEC3(new DataInputStream(new ByteArrayInputStream(nsec3b)), nsec3b, nsec3b.length);
        assertEquals(1, nsec3.hashAlgorithm);
        assertEquals(1, nsec3.flags);
        assertEquals(1, nsec3.iterations);
        assertArrayEquals(new byte[]{0x13, 0x37}, nsec3.salt);
        assertArrayEquals(new byte[]{0x42, 0x42, 0x42, 0x42, 0x42}, nsec3.nextHashed);
        assertArrayEquals(new TYPE[]{TYPE.A}, nsec3.types);

        assertEquals("1 1 1 - ", new NSEC3((byte) 1, (byte) 1, 1, new byte[0], new byte[0], new TYPE[0]).toString());
    }

    @Test
    public void testNsec3ParamRecord() throws Exception {
        NSEC3PARAM nsec3param = new NSEC3PARAM((byte) 1, (byte) 1, 1, new byte[0]);
        assertEquals("1 1 1 -", nsec3param.toString());
        assertEquals(TYPE.NSEC3PARAM, nsec3param.getType());
        byte[] nsec3paramb = nsec3param.toByteArray();
        nsec3param = new NSEC3PARAM(new DataInputStream(new ByteArrayInputStream(nsec3paramb)), nsec3paramb, nsec3paramb.length);
        assertEquals(1, nsec3param.hashAlgorithm);
        assertEquals(1, nsec3param.flags);
        assertEquals(1, nsec3param.iterations);
        assertEquals(0, nsec3param.salt.length);

        assertEquals("1 1 1 1337", new NSEC3PARAM((byte) 1, (byte) 1, 1, new byte[]{0x13, 0x37}).toString());
    }

    @Test
    public void testOpenpgpkeyRecord() throws Exception {
        OPENPGPKEY openpgpkey = new OPENPGPKEY(new byte[]{0x13, 0x37});
        assertEquals("Ezc=", openpgpkey.toString());
        assertEquals(TYPE.OPENPGPKEY, openpgpkey.getType());
        byte[] openpgpkeyb = openpgpkey.toByteArray();
        openpgpkey = new OPENPGPKEY(new DataInputStream(new ByteArrayInputStream(openpgpkeyb)), openpgpkeyb, openpgpkeyb.length);
        assertArrayEquals(new byte[]{0x13, 0x37}, openpgpkey.publicKeyPacket);
    }

    @Test
    public void testPtrRecord() throws Exception {
        PTR ptr = new PTR("ptr.example.com");
        assertEquals("ptr.example.com.", ptr.toString());
        assertEquals(TYPE.PTR, ptr.getType());
        byte[] ptrb = ptr.toByteArray();
        ptr = new PTR(new DataInputStream(new ByteArrayInputStream(ptrb)), ptrb, ptrb.length);
        assertEquals("ptr.example.com", ptr.name);
    }

    @Test
    public void testRrsigRecord() throws Exception {
        RRSIG rrsig = new RRSIG(TYPE.A, (byte) 8, (byte) 2, 3600, new Date(1000), new Date(0), 42, "example.com", new byte[]{42});
        // TODO: Compare with real Base64 once done
        assertEquals("A 8 2 3600 19700101000001 19700101000000 42 example.com. " + Base64.encodeToString(rrsig.signature), rrsig.toString());
        assertEquals(TYPE.RRSIG, rrsig.getType());
        byte[] rrsigb = rrsig.toByteArray();
        rrsig = new RRSIG(new DataInputStream(new ByteArrayInputStream(rrsigb)), rrsigb, rrsigb.length);
        assertEquals(TYPE.A, rrsig.typeCovered);
        assertEquals(8, rrsig.algorithm);
        assertEquals(2, rrsig.labels);
        assertEquals(3600, rrsig.originalTtl);
        assertEquals(new Date(1000), rrsig.signatureExpiration);
        assertEquals(new Date(0), rrsig.signatureInception);
        assertEquals(42, rrsig.keyTag);
        assertEquals("example.com", rrsig.signerName);
        assertArrayEquals(new byte[]{42}, rrsig.signature);
    }

    @Test
    public void testSoaRecord() throws Exception {
        SOA soa = new SOA("sns.dns.icann.org", "noc.dns.icann.org", 2015060341, 7200, 3600, 1209600, 3600);
        assertEquals("sns.dns.icann.org. noc.dns.icann.org. 2015060341 7200 3600 1209600 3600", soa.toString());
        assertEquals(TYPE.SOA, soa.getType());
        byte[] soab = soa.toByteArray();
        soa = new SOA(new DataInputStream(new ByteArrayInputStream(soab)), soab, soab.length);
        assertEquals("sns.dns.icann.org", soa.mname);
        assertEquals("noc.dns.icann.org", soa.rname);
        assertEquals(2015060341, soa.serial);
        assertEquals(7200, soa.refresh);
        assertEquals(3600, soa.retry);
        assertEquals(1209600, soa.expire);
        assertEquals(3600, soa.minimum);
    }

    @Test
    public void testSrvRecord() throws Exception {
        SRV srv = new SRV(30, 31, 5222, "hermes.jabber.org");
        assertEquals("30 31 5222 hermes.jabber.org.", srv.toString());
        assertEquals(TYPE.SRV, srv.getType());
        byte[] srvb = srv.toByteArray();
        srv = new SRV(new DataInputStream(new ByteArrayInputStream(srvb)), srvb, srvb.length);
        assertEquals(30, srv.priority);
        assertEquals(31, srv.weight);
        assertEquals(5222, srv.port);
        assertEquals("hermes.jabber.org", srv.name);
    }

    @Test
    public void testTlsaRecord() throws Exception {
        TLSA tlsa = new TLSA((byte) 1, (byte) 1, (byte) 1, new byte[]{0x13, 0x37});
        assertEquals("1 1 1 1337", tlsa.toString());
        assertEquals(TYPE.TLSA, tlsa.getType());
        byte[] tlsab = tlsa.toByteArray();
        tlsa = new TLSA(new DataInputStream(new ByteArrayInputStream(tlsab)), tlsab, tlsab.length);
        assertEquals(1, tlsa.certUsage);
        assertEquals(1, tlsa.selector);
        assertEquals(1, tlsa.matchingType);
        assertArrayEquals(new byte[]{0x13, 0x37}, tlsa.certificateAssociation);
    }
}
