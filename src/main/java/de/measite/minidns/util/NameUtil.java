package de.measite.minidns.util;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.IDN;
import java.util.HashSet;
import java.util.Arrays;

/**
 * Utilities related to internationalized domain names and dns name handling.
 */
public class NameUtil {

    /**
     * Retrieve the rough binary length of a string
     * (length + 2 bytes length prefix).
     * @param name The name string.
     * @return The binary size of the string (length + 2).
     */
    public static int size(String name) {
        return name.length() + 2;
    }

    /**
     * Check if two internationalized domain names are equal, possibly causing
     * a serialization of both domain names.
     * @param name1 The first domain name.
     * @param name2 The second domain name.
     * @return True if both domain names are the same.
     */
    public static boolean idnEquals(String name1, String name2) {
        if (name1 == name2) return true; // catches null, null
        if (name1 == null) return false;
        if (name2 == null) return false;
        if (name1.equals(name2)) return true;

        try {
            return Arrays.equals(toByteArray(name1),toByteArray(name2));
        } catch (IOException e) {
            return false; // impossible
        }
    }

    /**
     * Serialize a domain name under IDN rules.
     * @param name The domain name.
     * @return The binary domain name representation.
     * @throws IOException Should never happen.
     */
    public static byte[] toByteArray(String name) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(64);
        DataOutputStream dos = new DataOutputStream(baos);
        for (String s: name.split("[.\u3002\uFF0E\uFF61]")) {
            byte[] buffer = IDN.toASCII(s).getBytes();
            dos.writeByte(buffer.length);
            dos.write(buffer);
        }
        dos.writeByte(0);
        dos.flush();
        return baos.toByteArray();
    }

    /**
     * Parse a domain name starting at the current offset and moving the input
     * stream pointer past this domain name (even if cross references occure).
     * @param dis The input stream.
     * @param data The raw data (for cross references).
     * @return The domain name string.
     * @throws IOException Should never happen.
     */
    public static String parse(DataInputStream dis, byte data[]) 
        throws IOException
    {
        int c = dis.readUnsignedByte();
        if ((c & 0xc0) == 0xc0) {
            c = ((c & 0x3f) << 8) + dis.readUnsignedByte();
            HashSet<Integer> jumps = new HashSet<Integer>();
            jumps.add(c);
            return parse(data, c, jumps);
        }
        if (c == 0) {
            return "";
        }
        byte b[] = new byte[c];
        dis.readFully(b);
        String s = IDN.toUnicode(new String(b));
        String t = parse(dis, data);
        if (t.length() > 0) {
            s = s + "." + t;
        }
        return s;
    }

    /**
     * Parse a domain name starting at the given offset. 
     * @param data The raw data.
     * @param offset The offset.
     * @param jumps The list of jumps (by now).
     * @return The parsed domain name.
     * @throws IllegalStateException on cycles.
     */
    public static String parse(
        byte data[],
        int offset,
        HashSet<Integer> jumps
    ) {
        int c = data[offset] & 0xff;
        if ((c & 0xc0) == 0xc0) {
            c = ((c & 0x3f) << 8) + (data[offset + 1] & 0xff);
            if (jumps.contains(c)) {
                throw new IllegalStateException("Cyclic offsets detected.");
            }
            jumps.add(c);
            return parse(data, c, jumps);
        }
        if (c == 0) {
            return "";
        }
        String s = new String(data,offset + 1, c);
        String t = parse(data, offset + 1 + c, jumps);
        if (t.length() > 0) {
            s = s + "." + t;
        }
        return s;
    }

}
