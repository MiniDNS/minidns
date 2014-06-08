package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

public class CNAME implements Data {

    protected String name;

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
        this.name = NameUtil.parse(dis, data);
    }

    @Override
    public TYPE getType() {
        return TYPE.CNAME;
    }

    @Override
    public String toString() {
        return "to \"" + name + "\"";
    }

}
