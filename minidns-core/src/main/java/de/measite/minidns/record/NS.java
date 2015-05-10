package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;

/**
 * Nameserver record.
 */
public class NS extends CNAME {

    public NS(DataInputStream dis, byte[] data, int length) throws IOException {
        super(dis, data, length);
    }

    @Override
    public TYPE getType() {
        return TYPE.NS;
    }

}
