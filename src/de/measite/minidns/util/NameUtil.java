package de.measite.minidns.util;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.IDN;
import java.util.HashSet;

public class NameUtil {

    public static int size(String name) {
        return name.length() + 2;
    }

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

    public static String parse(
        byte data[],
        int offset,
        HashSet<Integer> jumps
    ) {
        int c = data[offset] & 0xff;
        if ((c & 0xc0) == 0xc0) {
            c = ((c & 0x3f) << 8) + data[offset + 1];
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
