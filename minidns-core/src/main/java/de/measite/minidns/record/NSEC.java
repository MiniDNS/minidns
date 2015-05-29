package de.measite.minidns.record;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

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

    /**
     * The RR types existing at the owner name.
     */
    public final TYPE[] types;

    public NSEC(DataInputStream dis, byte[] data, int length) throws IOException {
        next = NameUtil.parse(dis, data);

        ArrayList<TYPE> typeList = new ArrayList<TYPE>();
        int read = NameUtil.size(next);
        while (length > read) {
            int windowBlock = dis.readUnsignedByte();
            int bitmapLength = dis.readUnsignedByte();
            for (int i = 0; i < bitmapLength; i++) {
                int b = dis.readUnsignedByte();
                for (int j = 0; j < 8; j++) {
                    if (((b >> j) & 0x1) > 0) {
                        typeList.add(TYPE.getType((windowBlock >> 8) + (i * 8) + (7 - j)));
                    }
                }
            }
            read += bitmapLength + 2;
        }
        types = typeList.toArray(new TYPE[typeList.size()]);
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
        StringBuilder sb = new StringBuilder("NSEC " + next);
        for (TYPE type : types) {
            sb.append(' ').append(type.name());
        }
        return sb.toString();
    }
}
