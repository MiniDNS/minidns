package de.measite.minidns.record;

import de.measite.minidns.Record.TYPE;

import java.io.DataInputStream;
import java.io.IOException;

/**
 * OPT payload (see RFC 2671 for details)
 */
public class OPT implements Data {

    /**
     * Raw encoded RDATA of an OPT RR
     */
    public final byte[] encodedOptData;
    
    public OPT() {
        encodedOptData = new byte[0];
    }

    public OPT(DataInputStream dis, byte[] data, int payloadLength) throws IOException {
        encodedOptData = new byte[payloadLength];
        dis.read(encodedOptData);
    }

    @Override
    public TYPE getType() {
        return TYPE.OPT;
    }

    @Override
    public byte[] toByteArray() {
        return encodedOptData;
    }
}
