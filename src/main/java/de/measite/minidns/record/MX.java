package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

/**
 * MX record payload (mail service pointer).
 */
public class MX implements Data {

    /**
     * The priority of this service. Lower values mean higher priority.
     */
    public final int priority;

    /**
     * The name of the target server.
     */
    public final String name;

    public MX(DataInputStream dis, byte[] data, int length)
        throws IOException
    {
        this.priority = dis.readUnsignedShort();
        this.name = NameUtil.parse(dis, data);
    }

    @Override
    public byte[] toByteArray() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public String toString() {
        return "MX " + name + " p:" + priority;
    }

    @Override
    public TYPE getType() {
        return TYPE.MX;
    }

}
