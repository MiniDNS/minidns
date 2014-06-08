package de.measite.minidns;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import de.measite.minidns.Record.CLASS;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

public class Question {

    private String name;

    private TYPE type;

    private CLASS clazz = CLASS.IN;

    public TYPE getType() {
        return type;
    }

    public void setType(TYPE type) {
        this.type = type;
    }

    public CLASS getClazz() {
        return clazz;
    }

    public void setClazz(CLASS clazz) {
        this.clazz = clazz;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void parse(DataInputStream dis, byte[] data) throws IOException {
        this.name = NameUtil.parse(dis, data);
        this.type = TYPE.getType(dis.readUnsignedShort());
        this.clazz = CLASS.getClass(dis.readUnsignedShort());
    }

    public byte[] toByteArray() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        DataOutputStream dos = new DataOutputStream(baos);

        dos.write(NameUtil.toByteArray(this.name));
        dos.writeShort(type.getValue());
        dos.writeShort(clazz.getValue());

        dos.flush();
        return baos.toByteArray();
    }

}
