package de.measite.minidns.record;

import de.measite.minidns.Record.TYPE;

import java.io.DataInputStream;
import java.io.IOException;

/**
 * DNSKEY record payload
 */
public class DNSKEY implements Data {
    public static final short FLAG_SECURE_ENTRY_POINT = 0x1;
    public static final short FLAG_REVOKE = 0x80;
    public static final short FLAG_ZONE = 0x100;

    public final short flags;
    public final byte protocol;
    public final byte algorithm;
    public final byte[] key;

    public DNSKEY(DataInputStream dis, byte[] data, int length) throws IOException {
        flags = dis.readShort();
        protocol = dis.readByte();
        algorithm = dis.readByte();
        key = new byte[length - 4];
        dis.readFully(key);
    }

    @Override
    public TYPE getType() {
        return TYPE.DNSKEY;
    }

    @Override
    public byte[] toByteArray() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public String toString() {
        // TODO: cross platform Base64 of key?
        return "DNSKEY " + flags + " " + protocol + " " + algorithm + " " + key + '}';
    }
}
