/*
 * Copyright 2015 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.record;

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.NameUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * NSEC record payload.
 */
public class NSEC implements Data {

    /**
     * The next owner name that contains a authoritative data or a delegation point.
     */
    public final String next;

    private final byte[] typeBitmap;

    /**
     * The RR types existing at the owner name.
     */
    public final TYPE[] types;

    public NSEC(DataInputStream dis, byte[] data, int length) throws IOException {
        next = NameUtil.parse(dis, data);

        typeBitmap = new byte[length - NameUtil.size(next)];
        if (dis.read(typeBitmap) != typeBitmap.length) throw new IOException();
        types = readTypeBitMap(typeBitmap);
    }

    public NSEC(String next, TYPE[] types) {
        this.next = next;
        this.types = types;
        this.typeBitmap = createTypeBitMap(types);
    }

    @Override
    public TYPE getType() {
        return TYPE.NSEC;
    }

    @Override
    public byte[] toByteArray() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.write(NameUtil.toByteArray(next));
            dos.write(typeBitmap);
        } catch (IOException e) {
            // Should never happen
            throw new RuntimeException(e);
        }

        return baos.toByteArray();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder()
                .append(next).append('.');
        for (TYPE type : types) {
            sb.append(' ').append(type);
        }
        return sb.toString();
    }

    static byte[] createTypeBitMap(TYPE[] types) {
        List<Integer> typeList = new ArrayList<Integer>();
        for (TYPE type : types) {
            typeList.add(type.getValue());
        }
        Collections.sort(typeList);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        try {
            int windowBlock = -1;
            byte[] bitmap = null;
            for (Integer type : typeList) {
                if (windowBlock == -1 || (type >> 8) != windowBlock) {
                    if (windowBlock != -1) writeOutBlock(bitmap, dos);
                    windowBlock = (type >> 8);
                    dos.writeByte(windowBlock);
                    bitmap = new byte[32];
                }
                int a = (type >> 3) % 32;
                int b = type % 8;
                bitmap[a] |= (128 >> b);
            }
            if (windowBlock != -1) writeOutBlock(bitmap, dos);
        } catch (IOException e) {
            // Should never happen.
            throw new RuntimeException(e);
        }

        return baos.toByteArray();
    }

    private static void writeOutBlock(byte[] values, DataOutputStream dos) throws IOException {
        int n = 0;
        for (int i = 0; i < values.length; i++) {
            if (values[i] != 0) n = i + 1;
        }
        dos.writeByte(n);
        for (int i = 0; i < n; i++) {
            dos.writeByte(values[i]);
        }
    }

    static TYPE[] readTypeBitMap(byte[] typeBitmap) throws IOException {
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
                        typeList.add(TYPE.getType((windowBlock << 8) + (i * 8) + (7 - j)));
                    }
                }
            }
            read += bitmapLength + 2;
        }
        return typeList.toArray(new TYPE[typeList.size()]);
    }
}
