package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

public class SRV implements Data {

    protected int priority;
    protected int weight;
    protected int port;
    protected String name;

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public int getWeight() {
        return weight;
    }

    public void setWeight(int weight) {
        this.weight = weight;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public byte[] toByteArray() {
        // TODO Auto-generated method stub
        return null;
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
