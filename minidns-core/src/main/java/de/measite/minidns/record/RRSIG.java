package de.measite.minidns.record;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

import java.io.DataInputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * RRSIG record payload
 */
public class RRSIG implements Data {

    /**
     * The type of RRset covered by this signature.
     */
    public final TYPE typeCovered;

    /**
     * The cryptographic algorithm used to create the signature.
     */
    public final byte algorithm;

    /**
     * The number of labels in the original RRSIG RR owner name.
     */
    public final byte labels;

    /**
     * The TTL of the covered RRset.
     */
    public final long /* unsigned int */ originalTtl;

    /**
     * The date and time this RRSIG records expires.
     */
    public final Date signatureExpiration;

    /**
     * The date and time this RRSIG records starts to be valid.
     */
    public final Date signatureInception;

    /**
     * The key tag value of the DNSKEY RR that validates this signature.
     */
    public final short keyTag;

    /**
     * The owner name of the DNSKEY RR that a validator is supposed to use.
     */
    public final String signerName;

    /**
     * Signature that covers RRSIG RDATA (excluding the signature field) and RRset data
     */
    public final byte[] signature;

    public RRSIG(DataInputStream dis, byte[] data, int length) throws IOException {
        typeCovered = TYPE.getType(dis.readUnsignedShort());
        algorithm = dis.readByte();
        labels = dis.readByte();
        originalTtl = dis.readInt() & 0xFFFFFFFFL;
        signatureExpiration = new Date((dis.readInt() & 0xFFFFFFFFL) * 1000);
        signatureInception = new Date((dis.readInt() & 0xFFFFFFFFL) * 1000);
        keyTag = dis.readShort();
        signerName = NameUtil.parse(dis, data);
        int sigSize = length - NameUtil.size(signerName) - 18;
        signature = new byte[sigSize];
        dis.read(signature);
    }

    @Override
    public TYPE getType() {
        return TYPE.RRSIG;
    }

    @Override
    public String toString() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYYMMddHHmmss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        // TODO: cross platform Base64 of key?
        return "RRSIG " + typeCovered.name() + " " + algorithm + " " + labels + " " + originalTtl + " "
                + dateFormat.format(signatureExpiration) + " " + dateFormat.format(signatureInception) + " " +
                keyTag + " " + signerName + " " + signature;
    }

    @Override
    public byte[] toByteArray() {
        throw new UnsupportedOperationException("Not implemented yet");
    }
}
