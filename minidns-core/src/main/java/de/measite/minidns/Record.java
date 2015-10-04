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
package de.measite.minidns;

import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.DLV;
import de.measite.minidns.record.DNSKEY;
import de.measite.minidns.record.DS;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.MX;
import de.measite.minidns.record.NS;
import de.measite.minidns.record.NSEC;
import de.measite.minidns.record.NSEC3;
import de.measite.minidns.record.NSEC3PARAM;
import de.measite.minidns.record.OPENPGPKEY;
import de.measite.minidns.record.OPT;
import de.measite.minidns.record.PTR;
import de.measite.minidns.record.RRSIG;
import de.measite.minidns.record.SOA;
import de.measite.minidns.record.SRV;
import de.measite.minidns.record.TLSA;
import de.measite.minidns.record.TXT;
import de.measite.minidns.util.NameUtil;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Logger;

/**
 * A generic DNS record.
 */
public class Record {
    private static final Logger LOGGER = Logger.getLogger(Record.class.getName());

    /**
     * The record type.
     * @see <a href="http://www.iana.org/assignments/dns-parameters">IANA DNS Parameters</a>
     */
    public static enum TYPE {
        UNKNOWN(-1),
        A(1),
        NS(2),
        MD(3),
        MF(4),
        CNAME(5),
        SOA(6),
        MB(7),
        MG(8),
        MR(9),
        NULL(10),
        WKS(11),
        PTR(12),
        HINFO(13),
        MINFO(14),
        MX(15),
        TXT(16),
        RP(17),
        AFSDB(18),
        X25(19),
        ISDN(20),
        RT(21),
        NSAP(22),
        NSAP_PTR(23),
        SIG(24),
        KEY(25),
        PX(26),
        GPOS(27),
        AAAA(28),
        LOC(29),
        NXT(30),
        EID(31),
        NIMLOC(32),
        SRV(33),
        ATMA(34),
        NAPTR(35),
        KX(36),
        CERT(37),
        A6(38),
        DNAME(39),
        SINK(40),
        OPT(41),
        APL(42),
        DS(43),
        SSHFP(44),
        IPSECKEY(45),
        RRSIG(46),
        NSEC(47),
        DNSKEY(48),
        DHCID(49),
        NSEC3(50),
        NSEC3PARAM(51),
        TLSA(52),
        HIP(55),
        NINFO(56),
        RKEY(57),
        TALINK(58),
        CDS(59),
        CDNSKEY(60),
        OPENPGPKEY(61),
        CSYNC(62),
        SPF(99),
        UINFO(100),
        UID(101),
        GID(102),
        UNSPEC(103),
        NID(104),
        L32(105),
        L64(106),
        LP(107),
        EUI48(108),
        EUI64(109),
        TKEY(249),
        TSIG(250),
        IXFR(251),
        AXFR(252),
        MAILB(253),
        MAILA(254),
        ANY(255),
        URI(256),
        CAA(257),
        TA(32768),
        DLV(32769);

        /**
         * The value of this DNS record type.
         */
        private final int value;

        /**
         * Internal lookup table to map values to types.
         */
        private final static HashMap<Integer, TYPE> INVERSE_LUT =
                                        new HashMap<Integer, TYPE>();

        static {
            // Initialize the reverse lookup table.
            for(TYPE t: TYPE.values()) {
                INVERSE_LUT.put(t.getValue(), t);
            }
        }

        /**
         * Create a new record type.
         * @param value The binary value of this type.
         */
        private TYPE(int value) {
            this.value = value;
        }

        /**
         * Retrieve the binary value of this type.
         * @return The binary value.
         */
        public int getValue() {
            return value;
        }

        /**
         * Retrieve the symbolic type of the binary value.
         * @param value The binary type value.
         * @return The symbolic tpye.
         */
        public static TYPE getType(int value) {
            TYPE type = INVERSE_LUT.get(value);
            if (type == null) return UNKNOWN;
            return type;
        }
    }

    /**
     * The symbolic class of a DNS record (usually IN for Internet).
     */
    public static enum CLASS {
        IN(1),
        CH(3),
        HS(4),
        NONE(254),
        ANY(255);

        /**
         * Internal reverse lookup table to map binary class values to symbolic
         * names.
         */
        private final static HashMap<Integer, CLASS> INVERSE_LUT =
                                            new HashMap<Integer, CLASS>();

        static {
            // Initialize the interal reverse lookup table.
            for(CLASS c: CLASS.values()) {
                INVERSE_LUT.put(c.getValue(), c);
            }
        }

        /**
         * The binary value of this dns class.
         */
        private final int value;

        /**
         * Create a new DNS class based on a binary value.
         * @param value The binary value of this DNS class.
         */
        private CLASS(int value) {
            this.value = value;
        }

        /**
         * Retrieve the binary value of this DNS class.
         * @return The binary value of this DNS class.
         */
        public int getValue() {
            return value;
        }

        /**
         * Retrieve the symbolic DNS class for a binary class value.
         * @param value The binary DNS class value.
         * @return The symbolic class instance.
         */
        public static CLASS getClass(int value) {
            return INVERSE_LUT.get(value);
        }

    }

    /**
     * The generic name of this record.
     */
    public final String name;

    /**
     * The type (and payload type) of this record.
     */
    public final TYPE type;

    /**
     * The record class (usually CLASS.IN).
     */
    public final CLASS clazz;

    /**
     * The value of the class field of a RR.
     * 
     * According to RFC 2671 (OPT RR) this is not necessarily representable
     * using clazz field and unicastQuery bit
     */
    public final int clazzValue;

    /**
     * The ttl of this record.
     */
    public final long ttl;

    /**
     * The payload object of this record.
     */
    public final Data payloadData;

    /**
     * MDNS defines the highest bit of the class as the unicast query bit.
     */
    protected boolean unicastQuery;

    /**
     * Parse a given record based on the full message data and the current
     * stream position.
     * @param dis The DataInputStream positioned at the first record byte.
     * @param data The full message data.
     * @throws IOException In case of malformed replies.
     */
    public Record(DataInputStream dis, byte[] data) throws IOException {
        this.name = NameUtil.parse(dis, data);
        int typeValue = dis.readUnsignedShort();
        this.type = TYPE.getType(typeValue);
        this.clazzValue = dis.readUnsignedShort();
        this.clazz = CLASS.getClass(clazzValue & 0x7fff);
        this.unicastQuery = (clazzValue & 0x8000) > 0;
        if (this.clazz == null) {
            LOGGER.fine("Unknown class " + clazzValue);
        }
        this.ttl = (((long)dis.readUnsignedShort()) << 16) +
                   dis.readUnsignedShort();
        int payloadLength = dis.readUnsignedShort();
        switch (this.type) {
            case SOA:
                this.payloadData = new SOA(dis, data, payloadLength);
                break;
            case SRV:
                this.payloadData = new SRV(dis, data, payloadLength);
                break;
            case MX:
                this.payloadData = new MX(dis, data, payloadLength);
                break;
            case AAAA:
                this.payloadData = new AAAA(dis, data, payloadLength);
                break;
            case A:
                this.payloadData = new A(dis, data, payloadLength);
                break;
            case NS:
                this.payloadData = new NS(dis, data, payloadLength);
                break;
            case CNAME:
                this.payloadData = new CNAME(dis, data, payloadLength);
                break;
            case PTR:
                this.payloadData = new PTR(dis, data, payloadLength);
                break;
            case TXT:
                this.payloadData = new TXT(dis, data, payloadLength);
                break;
            case OPT:
                this.payloadData = new OPT(dis, data, payloadLength);
                break;
            case DNSKEY:
                this.payloadData = new DNSKEY(dis, data, payloadLength);
                break;
            case RRSIG:
                this.payloadData = new RRSIG(dis, data, payloadLength);
                break;
            case DS:
                this.payloadData = new DS(dis, data, payloadLength);
                break;
            case NSEC:
                this.payloadData = new NSEC(dis, data, payloadLength);
                break;
            case NSEC3:
                this.payloadData = new NSEC3(dis, data, payloadLength);
                break;
            case NSEC3PARAM:
                this.payloadData = new NSEC3PARAM(dis, data, payloadLength);
                break;
            case TLSA:
                this.payloadData = new TLSA(dis, data, payloadLength);
                break;
            case OPENPGPKEY:
                this.payloadData = new OPENPGPKEY(dis, data, payloadLength);
                break;
            case DLV:
                this.payloadData = new DLV(dis, data, payloadLength);
                break;
            case UNKNOWN:
            default:
                this.payloadData = null;
                for (int i = 0; i < payloadLength; i++) {
                    dis.readByte();
                }
                break;
        }
    }

    public Record(String name, TYPE type, CLASS clazz, long ttl, Data payloadData, boolean unicastQuery) {
        this.name = name;
        this.type = type;
        this.clazz = clazz;
        this.ttl = ttl;
        this.payloadData = payloadData;
        this.unicastQuery = unicastQuery;
        this.clazzValue = clazz.getValue() + (unicastQuery ? 0x8000 : 0);
    }

    public Record(String name, TYPE type, int clazzValue, long ttl, Data payloadData) {
        this.name = name;
        this.type = type;
        this.clazz = CLASS.NONE;
        this.clazzValue = clazzValue;
        this.ttl = ttl;
        this.payloadData = payloadData;
    }

    public byte[] toByteArray() {
        if (payloadData == null) {
            throw new IllegalStateException("Empty Record has no byte representation");
        }
        byte[] payload = payloadData.toByteArray();
        ByteArrayOutputStream baos = new ByteArrayOutputStream(NameUtil.size(name) + 8 + payload.length);
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.write(NameUtil.toByteArray(name));
            dos.writeShort(type.getValue());
            dos.writeShort(clazzValue);
            dos.writeInt((int) ttl);
            dos.writeShort(payload.length);
            dos.write(payload);
        } catch (IOException e) {
            // Should never happen
            throw new RuntimeException(e);
        }
        return baos.toByteArray();
    }

    /**
     * Retrieve a textual representation of this resource record.
     * @return String
     */
    @Override
    public String toString() {
        return name + ".\t" + ttl + '\t' + clazz + '\t' + type + '\t' + payloadData;
    }

    /**
     * Check if this record answers a given query.
     * @param q The query.
     * @return True if this record is a valid answer.
     */
    public boolean isAnswer(Question q) {
        return ((q.type == type) || (q.type == TYPE.ANY)) &&
               ((q.clazz == clazz) || (q.clazz == CLASS.ANY)) &&
               (q.name.equals(name));
    }

    /**
     * See if this query/response was a unicast query (highest class bit set).
     * @return True if it is a unicast query/response record.
     */
    public boolean isUnicastQuery() {
        return unicastQuery;
    }

    /**
     * The generic record name, e.g. "measite.de".
     * @return The record name.
     */
    public String getName() {
        return name;
    }

    /**
     * The payload data, usually a subclass of data (A, AAAA, CNAME, ...).
     * @return The payload data.
     */
    public Data getPayload() {
        return payloadData;
    }

    /**
     * Retrieve the record ttl.
     * @return The record ttl.
     */
    public long getTtl() {
        return ttl;
    }

}
