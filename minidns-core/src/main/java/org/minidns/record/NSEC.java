/*
 * Copyright 2015-2024 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.record;

import org.minidns.dnsname.DnsName;
import org.minidns.record.Record.TYPE;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * NSEC record payload.
 */
public class NSEC extends Data {

    /**
     * The next owner name that contains a authoritative data or a delegation point.
     */
    public final DnsName next;

    /**
     * The type bitmap in wire format. If this NSEC was parsed, then those are the exact bytes as received. This is
     * important, as re-creating the bitmap from {@link #types} would lose the types unknown to MiniDNS, which would
     * cause the RRSIG covering this NSEC to fail to verify.
     */
    private final byte[] typeBitmap;

    /**
     * The RR types existing at the owner name. This only contains the types known to MiniDNS, see
     * {@link #typeValues} for all types.
     */
    public final List<TYPE> types;

    /**
     * The numeric values of all RR types existing at the owner name, including the ones unknown to MiniDNS.
     */
    public final List<Integer> typeValues;

    public static NSEC parse(DataInputStream dis, byte[] data, int length) throws IOException {
        DnsName next = DnsName.parse(dis, data);

        byte[] typeBitmap = new byte[length - next.size()];
        if (dis.read(typeBitmap) != typeBitmap.length) throw new IOException();
        List<Integer> typeValues = readTypeBitMap(typeBitmap);
        return new NSEC(next, typeBitmap, typeValues);
    }

    public NSEC(String next, List<TYPE> types) {
        this(DnsName.from(next), types);
    }

    public NSEC(String next, TYPE... types) {
        this(DnsName.from(next), Arrays.asList(types));
    }

    public NSEC(DnsName next, List<TYPE> types) {
        this(next, createTypeBitMap(types), toTypeValues(types));
    }

    private NSEC(DnsName next, byte[] typeBitmap, List<Integer> typeValues) {
        this.next = next;
        this.typeBitmap = typeBitmap;
        this.typeValues = Collections.unmodifiableList(typeValues);
        this.types = Collections.unmodifiableList(toKnownTypes(typeValues));
    }

    @Override
    public TYPE getType() {
        return TYPE.NSEC;
    }

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        next.writeToStream(dos);
        dos.write(typeBitmap);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder()
                .append(next).append('.');
        appendTypes(sb, typeValues);
        return sb.toString();
    }

    static List<Integer> toTypeValues(List<TYPE> types) {
        List<Integer> typeValues = new ArrayList<>(types.size());
        for (TYPE type : types) {
            typeValues.add(type.getValue());
        }
        return typeValues;
    }

    static List<TYPE> toKnownTypes(List<Integer> typeValues) {
        List<TYPE> types = new ArrayList<>(typeValues.size());
        for (int typeValue : typeValues) {
            TYPE type = TYPE.getType(typeValue);
            if (type == TYPE.UNKNOWN) {
                continue;
            }
            types.add(type);
        }
        return types;
    }

    /**
     * Append the given types to the given string builder. Types unknown to MiniDNS are written in the generic
     * "TYPE&lt;value&gt;" notation as per RFC 3597 § 5.
     *
     * @param sb the string builder.
     * @param typeValues the numeric values of the types.
     */
    static void appendTypes(StringBuilder sb, List<Integer> typeValues) {
        for (int typeValue : typeValues) {
            sb.append(' ');
            TYPE type = TYPE.getType(typeValue);
            if (type == TYPE.UNKNOWN) {
                sb.append("TYPE").append(typeValue);
            } else {
                sb.append(type);
            }
        }
    }

    @SuppressWarnings("NarrowingCompoundAssignment")
    static byte[] createTypeBitMap(List<TYPE> types) {
        List<Integer> typeList = toTypeValues(types);
        Collections.sort(typeList);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        try {
            int windowBlock = -1;
            byte[] bitmap = null;
            for (Integer type : typeList) {
                if (windowBlock == -1 || (type >> 8) != windowBlock) {
                    if (windowBlock != -1) writeOutBlock(bitmap, dos);
                    windowBlock = type >> 8;
                    dos.writeByte(windowBlock);
                    bitmap = new byte[32];
                }
                int a = (type >> 3) % 32;
                int b = type % 8;
                bitmap[a] |= (byte) (128 >> b);
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

    /**
     * Read the numeric values of all types in the given type bitmap, in ascending order.
     *
     * @param typeBitmap the type bitmap in wire format.
     * @return the numeric values of the types, including the ones unknown to MiniDNS.
     * @throws IOException if the type bitmap is malformed.
     */
    static List<Integer> readTypeBitMap(byte[] typeBitmap) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(typeBitmap));
        int read = 0;
        List<Integer> typeList = new ArrayList<>();
        while (typeBitmap.length > read) {
            int windowBlock = dis.readUnsignedByte();
            int bitmapLength = dis.readUnsignedByte();
            for (int i = 0; i < bitmapLength; i++) {
                int b = dis.readUnsignedByte();
                for (int j = 7; j >= 0; j--) {
                    if (((b >> j) & 0x1) > 0) {
                        int typeInt = (windowBlock << 8) + (i * 8) + (7 - j);
                        typeList.add(typeInt);
                    }
                }
            }
            read += bitmapLength + 2;
        }
        return typeList;
    }
}
