package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;

/**
 * A PTR record is handled like a CNAME
 */
public class PTR extends CNAME {

    public PTR(DataInputStream dis, byte[] data, int length) throws IOException {
        super(dis, data, length);
    }

    @Override
    public TYPE getType() {
        return TYPE.PTR;
    }

}
