package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

/**
 * SRV record payload (service pointer).
 */
public class SRV implements Data {

    /**
     * The priority of this service. Lower values mean higher priority.
     */
    public final int priority;

    /**
     * The weight of this service. Services with the same priority should be
     * balanced based on weight.
     */
    public final int weight;

    /**
     * The target port.
     */
    public final int port;

    /**
     * The target server.
     */
    public String name;

    @Override
    public byte[] toByteArray() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    public SRV(DataInputStream dis, byte[] data, int length)
        throws IOException
    {
        this.priority = dis.readUnsignedShort();
        this.weight = dis.readUnsignedShort();
        this.port = dis.readUnsignedShort();
        this.name = NameUtil.parse(dis, data);
    }

    @Override
    public String toString() {
        return "SRV " + name + ":" + port + " p:" + priority + " w:" + weight;
    }

    @Override
    public TYPE getType() {
        return TYPE.SRV;
    }

}
