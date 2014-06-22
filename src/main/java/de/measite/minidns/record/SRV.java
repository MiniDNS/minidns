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
     * The priority of this service.
     */
    protected int priority;

    /**
     * The weight of this service.
     */
    protected int weight;

    /**
     * The target port.
     */
    protected int port;

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
     * The weight of this service. Services with the same priority should be
     * balanced based on weight.
     * @return The weight of this service.
     */
    public int getWeight() {
        return weight;
    }

    /**
     * Set the weight of this service.
     * @param weight The new weight of this service.
     */
    public void setWeight(int weight) {
        this.weight = weight;
    }

    /**
     * The target port of this service.
     * @return The target port of this service.
     */
    public int getPort() {
        return port;
    }

    /**
     * Set the target port of this service.
     * @param port The new target port.
     */
    public void setPort(int port) {
        this.port = port;
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
