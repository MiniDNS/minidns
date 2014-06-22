package de.measite.minidns.record;

import de.measite.minidns.Record.TYPE;

/**
 * Nameserver record.
 */
public class NS extends CNAME {

    @Override
    public TYPE getType() {
        return TYPE.NS;
    }

}
