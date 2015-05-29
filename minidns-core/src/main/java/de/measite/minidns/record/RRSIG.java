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

    public final TYPE typeCovered;
    public final byte algorithm;
    public final byte labels;
    public final long /* unsigned int */ originalTtl;
    public final Date signatureExpiration;
    public final Date signatureInception;
    public final short keyTag;
    public final String signerName;
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
