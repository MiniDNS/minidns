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
import de.measite.minidns.util.Base64;
import de.measite.minidns.util.NameUtil;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * RRSIG record payload.
 */
public class RRSIG implements Data {

    /**
     * The type of RRset covered by this signature.
     */
    public final TYPE typeCovered;

    /**
     * The cryptographic algorithm used to create the signature.
     * 
     * See {@link de.measite.minidns.DNSSECConstants} for possible values.
     */
    public final byte algorithm;

    /**
     * The number of labels in the original RRSIG RR owner name.
     */
    public final byte labels;

    /**
     * The TTL of the covered RRset.
     */
    public final long /* unsigned int */ originalTtl;

    /**
     * The date and time this RRSIG records expires.
     */
    public final Date signatureExpiration;

    /**
     * The date and time this RRSIG records starts to be valid.
     */
    public final Date signatureInception;

    /**
     * The key tag value of the DNSKEY RR that validates this signature.
     */
    public final int /* unsigned short */  keyTag;

    /**
     * The owner name of the DNSKEY RR that a validator is supposed to use.
     */
    public final String signerName;

    /**
     * Signature that covers RRSIG RDATA (excluding the signature field) and RRset data.
     */
    public final byte[] signature;

    public RRSIG(DataInputStream dis, byte[] data, int length) throws IOException {
        typeCovered = TYPE.getType(dis.readUnsignedShort());
        algorithm = dis.readByte();
        labels = dis.readByte();
        originalTtl = dis.readInt() & 0xFFFFFFFFL;
        signatureExpiration = new Date((dis.readInt() & 0xFFFFFFFFL) * 1000);
        signatureInception = new Date((dis.readInt() & 0xFFFFFFFFL) * 1000);
        keyTag = dis.readUnsignedShort();
        signerName = NameUtil.parse(dis, data);
        int sigSize = length - NameUtil.size(signerName) - 18;
        signature = new byte[sigSize];
        if (dis.read(signature) != signature.length) throw new IOException();
    }

    public RRSIG(TYPE typeCovered, byte algorithm, byte labels, long originalTtl, Date signatureExpiration, 
                 Date signatureInception, int keyTag, String signerName, byte[] signature) {
        this.typeCovered = typeCovered;
        this.algorithm = algorithm;
        this.labels = labels;
        this.originalTtl = originalTtl;
        this.signatureExpiration = signatureExpiration;
        this.signatureInception = signatureInception;
        this.keyTag = keyTag;
        this.signerName = signerName;
        this.signature = signature;
    }

    @Override
    public TYPE getType() {
        return TYPE.RRSIG;
    }

    @Override
    public byte[] toByteArray() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            writePartialSignature(dos);
            dos.write(signature);
        } catch (IOException e) {
            // Should never happen
            throw new RuntimeException(e);
        }

        return baos.toByteArray();
    }

    public void writePartialSignature(DataOutputStream dos) throws IOException {
        dos.writeShort(typeCovered.getValue());
        dos.writeByte(algorithm);
        dos.writeByte(labels);
        dos.writeInt((int) originalTtl);
        dos.writeInt((int) (signatureExpiration.getTime()/1000));
        dos.writeInt((int) (signatureInception.getTime()/1000));
        dos.writeShort(keyTag);
        dos.write(NameUtil.toByteArray(signerName));
    }

    @Override
    public String toString() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        StringBuilder sb = new StringBuilder()
                .append(typeCovered).append(' ')
                .append(algorithm).append(' ')
                .append(labels).append(' ')
                .append(originalTtl).append(' ')
                .append(dateFormat.format(signatureExpiration)).append(' ')
                .append(dateFormat.format(signatureInception)).append(' ')
                .append(keyTag).append(' ')
                .append(signerName).append(". ")
                .append(Base64.encodeToString(signature));
        return sb.toString();
    }
}
