package de.measite.minidns.record;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;

/**
 * NSEC record payload
 */
public class NSEC implements Data {

    /**
     * The next owner name that contains a authoritative data or a delegation point
     */
    public final String next;

    private final byte[] typeBitmap;
    
    /**
     * The RR types existing at the owner name.
     */
    public final TYPE[] types;

    public NSEC(DataInputStream dis, byte[] data, int length) throws IOException {
        next = NameUtil.parse(dis, data);

        typeBitmap = new byte[length-NameUtil.size(next)];
        dis.read(typeBitmap);
        types = readTypeBitMap(typeBitmap);
    }

    @Override
    public TYPE getType() {
        return TYPE.NSEC;
    }

    @Override
    public byte[] toByteArray() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder()
                .append(next).append('.');
        for (TYPE type : types) {
            sb.append(' ').append(type.name());
        }
        return sb.toString();
    }

    public static TYPE[] readTypeBitMap(byte[] typeBitmap) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(typeBitmap));
        int read = 0;
        ArrayList<TYPE> typeList = new ArrayList<TYPE>();
        while (typeBitmap.length > read) {
            int windowBlock = dis.readUnsignedByte();
            int bitmapLength = dis.readUnsignedByte();
            for (int i = 0; i < bitmapLength; i++) {
                int b = dis.readUnsignedByte();
                for (int j = 0; j < 8; j++) {
                    if (((b >> j) & 0x1) > 0) {
                        TYPE type = TYPE.getType((windowBlock << 8) + (i * 8) + (7 - j));
                        if (type != null) {
                            typeList.add(type);
                        }
                    }
                }
            }
            read += bitmapLength + 2;
        }
        return typeList.toArray(new TYPE[typeList.size()]);
    }
}
