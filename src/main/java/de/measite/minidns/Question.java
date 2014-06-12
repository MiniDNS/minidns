package de.measite.minidns;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import de.measite.minidns.Record.CLASS;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

public class Question {

    private final String name;

    private final TYPE type;

    private final CLASS clazz;

    private byte[] byteArray;

    public Question(String name, TYPE type, CLASS clazz) {
        this.name = name;
        this.type = type;
        this.clazz = clazz;
    }

    public TYPE getType() {
        return type;
    }

    public CLASS getClazz() {
        return clazz;
    }

    public String getName() {
        return name;
    }

    public static Question parse(DataInputStream dis, byte[] data) throws IOException {
        String name = NameUtil.parse(dis, data);
        TYPE type = TYPE.getType(dis.readUnsignedShort());
        CLASS clazz = CLASS.getClass(dis.readUnsignedShort());
        return new Question (name, type, clazz);
    }

    public byte[] toByteArray() {
        if (byteArray == null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
            DataOutputStream dos = new DataOutputStream(baos);

            try {
                dos.write(NameUtil.toByteArray(this.name));
                dos.writeShort(type.getValue());
                dos.writeShort(clazz.getValue());
                dos.flush();
            } catch (IOException e) {
                // Should never happen
                throw new IllegalStateException(e);
            }
            byteArray = baos.toByteArray();
        }
        return byteArray;
    }

    @Override
    public int hashCode() {
        return toByteArray().hashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Question)) {
            return false;
        }
        return this.hashCode() == other.hashCode();
    }
}
