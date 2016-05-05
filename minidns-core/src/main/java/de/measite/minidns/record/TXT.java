/*
 * Copyright 2015-2016 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import de.measite.minidns.Record.TYPE;

/**
 *  A TXT record. Actually a binary blob containing extents, each of which is a one-byte count
 *  followed by that many bytes of data, which can usually be interpreted as ASCII strings
 *  but not always.
 */
public class TXT extends Data {

    private final byte[] blob;

    public static TXT parse(DataInputStream dis, int length) throws IOException {
        byte[] blob = new byte[length];
        dis.readFully(blob);
        return new TXT(blob);
    }

    public TXT(byte[] blob) {
        this.blob = blob;
    }

    public byte[] getBlob() {
        return blob.clone();
    }

    public String getText() {
        List<byte[]> extents = getExtents();
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < extents.size() - 1) {
            sb.append(new String(extents.get(i))).append(" / ");
            i++;
        }
        sb.append(new String(extents.get(i)));
        return sb.toString();
    }

    public List<byte[]> getExtents() {
        ArrayList<byte[]> extents = new ArrayList<byte[]>();
        int used = 0;
        while (used < blob.length) {
            int segLength = 0x00ff & blob[used];
            int end = ++used + segLength;
            byte[] extent = Arrays.copyOfRange(blob, used, end);
            extents.add(extent);
            used += segLength;
        }
        return extents;
    }

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        dos.write(blob);
    }

    @Override
    public TYPE getType() {
        return TYPE.TXT;
    }

    @Override
    public String toString() {
        return "\"" + getText() + "\"";
    }

}
