package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

/**
 * A PTR record is handled like a CNAME
 */
public class PTR extends CNAME {

    @Override
    public TYPE getType() {
        return TYPE.PTR;
    }

}
