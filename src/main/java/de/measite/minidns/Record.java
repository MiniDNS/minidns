package de.measite.minidns;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.NS;
import de.measite.minidns.record.PTR;
import de.measite.minidns.record.SRV;
import de.measite.minidns.record.TXT;
import de.measite.minidns.util.NameUtil;

/**
 * A generic DNS record.
 */
public class Record {

    private static final Logger LOGGER = Logger.getLogger(Client.class.getName());

    /**
     * The record type.
     * @see <a href="http://www.iana.org/assignments/dns-parameters">IANA DNS Parameters</a>
     */
    public static enum TYPE {
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
        HIP(55),
        NINFO(56),
        RKEY(57),
        TALINK(58),
        SPF(99),
        UINFO(100),
        UID(101),
        GID(102),
        TKEY(249),
        TSIG(250),
        IXFR(251),
        AXFR(252),
        MAILB(253),
        MAILA(254),
        ANY(255),
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

        /**
         * Initialize the reverse lookup table.
         */
        static {
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
            return INVERSE_LUT.get(value);
        }
    };

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

        /**
         * Initialize the interal reverse lookup table.
         */
        static {
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
    protected String name;

    /**
     * The type (and payload type) of this record.
     */
    protected TYPE type;

    /**
     * The record class (usually CLASS.IN).
     */
    protected CLASS clazz;

    /**
     * The ttl of this record.
     */
    protected long ttl;

    /**
     * The payload object of this record.
     */
    protected Data payloadData;

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
    public void parse(DataInputStream dis, byte[] data) throws IOException {
        this.name = NameUtil.parse(dis, data);
        this.type = TYPE.getType(dis.readUnsignedShort());
        int clazzValue = dis.readUnsignedShort();
        this.clazz = CLASS.getClass(clazzValue & 0x7fff);
        this.unicastQuery = (clazzValue & 0x8000) > 0;
        if (this.clazz == null) {
            LOGGER.log(Level.FINE, "Unknown class " + clazzValue);
        }
        this.ttl = (((long)dis.readUnsignedShort()) << 32) +
                   dis.readUnsignedShort();
        int payloadLength = dis.readUnsignedShort();
        switch (this.type) {
        case SRV:
            this.payloadData = new SRV();
            break;
        case AAAA:
            this.payloadData = new AAAA();
            break;
        case A:
            this.payloadData = new A();
            break;
        case NS:
            this.payloadData = new NS();
            break;
        case CNAME:
            this.payloadData = new CNAME();
            break;
        case PTR:
            this.payloadData = new PTR();
            break;
        case TXT:
            this.payloadData = new TXT();
            break;
        default:
            LOGGER.log(Level.FINE, "Unparsed type " + type);
            this.payloadData = null;
            for (int i = 0; i < payloadLength; i++) {
                dis.readByte();
            }
            break;
        }
        if (this.payloadData != null) {
            this.payloadData.parse(dis, data, payloadLength);
        }
    }

    /**
     * Retrieve a textual representation of this resource record.
     * @return String
     */
    @Override
    public String toString() {
        if (payloadData == null) {
            return "RR " + type + "/" + clazz;
        }
        return "RR " + type + "/" + clazz + ": " + payloadData.toString();
    };

    /**
     * Check if this record answers a given query.
     * @param q The query.
     * @return True if this record is a valid answer.
     */
    public boolean isAnswer(Question q) {
        return ((q.getType() == type) || (q.getType() == TYPE.ANY)) &&
               ((q.getClazz() == clazz) || (q.getClazz() == CLASS.ANY)) &&
               (q.getName().equals(name));
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
