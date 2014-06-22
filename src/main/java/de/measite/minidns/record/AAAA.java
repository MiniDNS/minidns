package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;

/**
 * AAAA payload (an ipv6 pointer).
 */
public class AAAA implements Data {

    /**
     * The ipv6 address.
     */
    private byte[] ip;

    @Override
    public TYPE getType() {
        return TYPE.AAAA;
    }

    @Override
    public byte[] toByteArray() {
        return ip;
    }

    @Override
    public void parse(DataInputStream dis, byte[] data, int length)
            throws IOException {
        ip = new byte[16];
        dis.readFully(ip);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ip.length; i += 2) {
            if (i != 0) {
                sb.append(':');
            }
            sb.append(Integer.toHexString(
                ((ip[i] & 0xff) << 8) + (ip[i + 1] & 0xff)
            ));
        }
        return sb.toString();
    }

}
