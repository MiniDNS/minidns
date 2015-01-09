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
     * The priority of this service.
     */
    protected int priority;

    /**
     * The target server.
     */
    protected String name;

    /**
     * The priority of this service. Lower values mean higher priority.
     * @return The priority.
     */
    public int getPriority() {
        return priority;
    }

    /**
     * Set the priority of this service entry. Lower values have higher priority.
     * @param priority The new priority.
     */
    public void setPriority(int priority) {
        this.priority = priority;
    }

    /**
     * The name of the target server.
     * @return The target servers name.
     */
    public String getName() {
        return name;
    }

    /**
     * Set the name of the target server.
     * @param name The new target servers name.
     */
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public byte[] toByteArray() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public void parse(DataInputStream dis, byte[] data, int length)
        throws IOException
    {
        this.priority = dis.readUnsignedShort();
        this.name = NameUtil.parse(dis, data);
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
