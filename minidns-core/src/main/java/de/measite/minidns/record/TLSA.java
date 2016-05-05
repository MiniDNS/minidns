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

import de.measite.minidns.Record;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

public class TLSA extends Data {

    public static final byte CERT_USAGE_CA_CONSTRAINT = 0;
    public static final byte CERT_USAGE_SERVICE_CERTIFICATE_CONSTRAINT = 1;
    public static final byte CRET_USAGE_TRUST_ANCHOR_ASSERTION = 2;
    public static final byte CERT_USAGE_DOMAIN_ISSUED_CERTIFICATE = 3;

    public static final byte SELECTOR_FULL_CERTIFICATE = 0;
    public static final byte SELECTOR_SUBJECT_PUBLIC_KEY_INFO = 1;

    public static final byte MATCHING_TYPE_NO_HASH = 0;
    public static final byte MATCHING_TYPE_SHA_256 = 1;
    public static final byte MATCHING_TYPE_SHA_512 = 2;

    /**
     * The provided association that will be used to match the certificate presented in
     * the TLS handshake.
     */
    public final byte certUsage;

    /**
     * Which part of the TLS certificate presented by the server will be matched against the
     * association data.
     */
    public final byte selector;

    /**
     * How the certificate association is presented.
     */
    public final byte matchingType;

    /**
     * The "certificate association data" to be matched.
     */
    private final byte[] certificateAssociation;

    public static TLSA parse(DataInputStream dis, int length) throws IOException {
        byte certUsage = dis.readByte();
        byte selector = dis.readByte();
        byte matchingType = dis.readByte();
        byte[] certificateAssociation = new byte[length - 3];
        if (dis.read(certificateAssociation) != certificateAssociation.length) throw new IOException();
        return new TLSA(certUsage, selector, matchingType, certificateAssociation);
    }

    TLSA(byte certUsage, byte selector, byte matchingType, byte[] certificateAssociation) {
        this.certUsage = certUsage;
        this.selector = selector;
        this.matchingType = matchingType;
        this.certificateAssociation = certificateAssociation;
    }

    @Override
    public Record.TYPE getType() {
        return Record.TYPE.TLSA;
    }

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        dos.writeByte(certUsage);
        dos.writeByte(selector);
        dos.writeByte(matchingType);
        dos.write(certificateAssociation);
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append(certUsage).append(' ')
                .append(selector).append(' ')
                .append(matchingType).append(' ')
                .append(new BigInteger(1, certificateAssociation).toString(16)).toString();
    }

    public byte[] getCertificateAssociation() {
        return certificateAssociation.clone();
    }

    public boolean certificateAssociationEquals(byte[] otherCertificateAssociation) {
        return Arrays.equals(certificateAssociation, otherCertificateAssociation);
    }
}
