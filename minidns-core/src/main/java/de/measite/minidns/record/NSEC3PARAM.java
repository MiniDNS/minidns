package de.measite.minidns.record;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.Base32;

import java.io.DataInputStream;
import java.io.IOException;

public class NSEC3PARAM implements Data {

    /**
     * The cryptographic hash algorithm used.
     */
    public final byte hashAlgorithm;

    public final byte flags;

    /**
     * The number of iterations the hash algorithm is applied.
     */
    public final int /* unsigned short */ iterations;

    /**
     * The salt appended to the next owner name before hashing.
     */
    public final byte[] salt;

    public NSEC3PARAM(DataInputStream dis, byte[] data, int length) throws IOException {
        hashAlgorithm = dis.readByte();
        flags = dis.readByte();
        iterations = dis.readUnsignedShort();
        int saltLength = dis.readUnsignedByte();
        salt = new byte[saltLength];
        dis.read(salt);
    }
    
    @Override
    public TYPE getType() {
        return TYPE.NSEC3PARAM;
    }

    @Override
    public byte[] toByteArray() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("NSEC3PARAM ");
        sb.append(hashAlgorithm).append(' ')
                .append(flags).append(' ')
                .append(iterations).append(' ')
                .append(Base32.encodeToString(salt));
        return sb.toString();
    }
}
