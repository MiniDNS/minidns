package de.measite.minidns;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

import de.measite.minidns.Record.CLASS;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

/**
 * A DNS question (request).
 */
public class Question {

    /**
     * The question string (e.g. "measite.de").
     */
    private final String name;

    /**
     * The question type (e.g. A).
     */
    private final TYPE type;

    /**
     * The question class (usually IN / internet).
     */
    private final CLASS clazz;

    /**
     * UnicastQueries have the highest bit of the CLASS field set to 1.
     */
    private final boolean unicastQuery;

    /**
     * Cache for the serialized object.
     */
    private byte[] byteArray;

    /**
     * Create a dns question for the given name/type/class.
     * @param name The name e.g. "measite.de".
     * @param type The type, e.g. A.
     * @param clazz The class, usually IN (internet).
     */
    public Question(String name, TYPE type, CLASS clazz, boolean unicastQuery) {
        this.name = name;
        this.type = type;
        this.clazz = clazz;
        this.unicastQuery = unicastQuery;
    }

    /**
     * Create a dns question for the given name/type/class.
     * @param name The name e.g. "measite.de".
     * @param type The type, e.g. A.
     * @param clazz The class, usually IN (internet).
     */
    public Question(String name, TYPE type, CLASS clazz) {
        this(name, type, clazz, false);
    }

    /**
     * Create a dns question for the given name/type/IN (internet class).
     * @param name The name e.g. "measite.de".
     * @param type The type, e.g. A.
     */
    public Question(String name, TYPE type) {
        this(name, type, CLASS.IN);
    }

    /**
     * Retrieve the type of this question.
     * @return The type.
     */
    public TYPE getType() {
        return type;
    }

    /**
     * Retrieve the class of this dns question (usually internet).
     * @return The class of this dns question.
     */
    public CLASS getClazz() {
        return clazz;
    }

    /**
     * Retrieve the name of this dns question (e.g. "measite.de").
     * @return The name of this dns question.
     */
    public String getName() {
        return name;
    }

    /**
     * Parse a byte array and rebuild the dns question from it.
     * @param dis The input stream.
     * @param data The plain data (for dns name references).
     * @return The parsed dns question.
     * @throws IOException On errors (read outside of packet).
     */
    public static Question parse(DataInputStream dis, byte[] data) throws IOException {
        String name = NameUtil.parse(dis, data);
        TYPE type = TYPE.getType(dis.readUnsignedShort());
        CLASS clazz = CLASS.getClass(dis.readUnsignedShort());
        return new Question (name, type, clazz);
    }

    /**
     * Generate a binary paket for this dns question.
     * @return The dns question.
     */
    public byte[] toByteArray() {
        if (byteArray == null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
            DataOutputStream dos = new DataOutputStream(baos);

            try {
                dos.write(NameUtil.toByteArray(this.name));
                dos.writeShort(type.getValue());
                dos.writeShort(clazz.getValue() | (unicastQuery ? (1 << 15) : 0));
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
        return Arrays.hashCode(toByteArray());
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Question)) {
            return false;
        }
        byte t[] = toByteArray();
        byte o[] = ((Question)other).toByteArray();
        return Arrays.equals(t, o);
    }

    @Override
    public String toString() {
        return "Question/" + clazz + "/" + type + ": " + name;
    }
}
