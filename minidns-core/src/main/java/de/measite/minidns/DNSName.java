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
package de.measite.minidns;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.IDN;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;

public class DNSName implements CharSequence, Serializable, Comparable<DNSName> {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    /**
     * @see <a href="https://www.ietf.org/rfc/rfc3490.txt">RFC 3490 § 3.1 1.</a>
     */
    private static final String LABEL_SEP_REGEX = "[.\u3002\uFF0E\uFF61]";

    public static final int MAX_LABELS = 128;

    public static final DNSName EMPTY = new DNSName("", false);

    public static final DNSName ROOT = new DNSName(".", false);

    /**
     * The DNS name in ASCII Compatible Encoding (ACE).
     */
    public final String ace;

    private transient byte[] bytes;

    private transient String idn;

    private transient String domainpart;

    private transient String hostpart;

    /**
     * The labels in <b>reverse</b> order.
     */
    private transient String[] labels;

    private transient int hashCode;

    private int size = -1;

    private DNSName(String name) {
        this(name, false);
    }

    private DNSName(String name, boolean inIdnForm) {
        if (inIdnForm) {
            ace = IDN.toASCII(name);
        } else {
            ace = name.toLowerCase(Locale.US);
        }
    }

    private DNSName(String[] labels) {
        this.labels = labels;

        int size = 0;
        for (String label : labels) {
            size += label.length() + 1;
        }
        StringBuilder sb = new StringBuilder(size);
        for (int i = labels.length - 1; i >= 0; i--) {
            sb.append(labels[i]).append('.');
        }
        sb.setLength(sb.length() - 1);
        ace = sb.toString();
    }

    public void writeToStream(OutputStream os) throws IOException {
        setBytesIfRequired();
        os.write(bytes);
    }

    /**
     * Serialize a domain name under IDN rules.
     *
     * @return The binary domain name representation.
     */
    public byte[] getBytes() {
        setBytesIfRequired();
        return bytes.clone();
    }

    private void setBytesIfRequired() {
        if (bytes != null)
            return;

        ByteArrayOutputStream baos = new ByteArrayOutputStream(64);
        setLabelsIfRequired();
        for (int i = labels.length - 1; i >= 0; i--) {
            byte[] buffer = labels[i].getBytes();
            baos.write(buffer.length);
            baos.write(buffer, 0, buffer.length);
        }

        baos.write(0);
        bytes = baos.toByteArray();
    }

    private void setLabelsIfRequired() {
        if (labels != null) return;

        if (isRootLabel()) {
            labels = new String[0];
            return;
        }

        labels = ace.split(LABEL_SEP_REGEX, MAX_LABELS);

        // Reverse the labels, so that 'foo, example, org' becomes 'org, example, foo'.
        for (int i = 0; i < labels.length / 2; i++) {
            String t = labels[i];
            int j = labels.length - i - 1;
            labels[i] = labels[j];
            labels[j] = t;
        }
    }

    public String asIdn() {
        if (idn != null)
            return idn;

        idn = IDN.toUnicode(ace);
        return idn;
    }

    /**
     * Domainpart in ACE representation.
     *
     * @return the domainpart in ACE representation.
     */
    public String getDomainpart() {
        setHostnameAndDomainpartIfRequired();
        return domainpart;
    }

    /**
     * Hostpart in ACE representation.
     *
     * @return the hostpart in ACE representation.
     */
    public String getHostpart() {
        setHostnameAndDomainpartIfRequired();
        return hostpart;
    }

    private void setHostnameAndDomainpartIfRequired() {
        if (hostpart != null) return;

        String[] parts = ace.split(LABEL_SEP_REGEX, 2);
        hostpart = parts[0];
        if (parts.length > 1) {
            domainpart = parts[1];
        } else {
            domainpart = "";
        }
    }

    public int size() {
        if (size < 0) {
            if (isRootLabel()) {
                size = 1;
            } else {
                size = ace.length() + 2;
            }
        }
        return size;
    }

    @Override
    public int length() {
        return ace.length();
    }

    @Override
    public char charAt(int index) {
        return ace.charAt(index);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        return ace.subSequence(start, end);
    }

    @Override
    public String toString() {
        return ace;
    }

    public static DNSName from(CharSequence name) {
        return from(name.toString());
    }

    public static DNSName from(String name) {
        return new DNSName(name, true);
    }

    public static DNSName from(DNSName left, DNSName right) {
        left.setLabelsIfRequired();
        right.setLabelsIfRequired();

        String[] labels = new String[left.labels.length + right.labels.length];
        System.arraycopy(right.labels, 0, labels, 0, right.labels.length);
        System.arraycopy(left.labels, 0, labels, right.labels.length, left.labels.length);
        return new DNSName(labels);
    }

    /**
     * Parse a domain name starting at the current offset and moving the input
     * stream pointer past this domain name (even if cross references occure).
     *
     * @param dis  The input stream.
     * @param data The raw data (for cross references).
     * @return The domain name string.
     * @throws IOException Should never happen.
     */
    public static DNSName parse(DataInputStream dis, byte data[])
            throws IOException {
        int c = dis.readUnsignedByte();
        if ((c & 0xc0) == 0xc0) {
            c = ((c & 0x3f) << 8) + dis.readUnsignedByte();
            HashSet<Integer> jumps = new HashSet<Integer>();
            jumps.add(c);
            return parse(data, c, jumps);
        }
        if (c == 0) {
            return DNSName.EMPTY;
        }
        byte b[] = new byte[c];
        dis.readFully(b);
        String s = IDN.toUnicode(new String(b));
        DNSName t = parse(dis, data);
        if (t.length() > 0) {
            s = s + "." + t;
        }
        return new DNSName(s);
    }

    /**
     * Parse a domain name starting at the given offset.
     *
     * @param data   The raw data.
     * @param offset The offset.
     * @param jumps  The list of jumps (by now).
     * @return The parsed domain name.
     * @throws IllegalStateException on cycles.
     */
    private static DNSName parse(byte data[], int offset, HashSet<Integer> jumps)
            throws IllegalStateException {
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
            return DNSName.EMPTY;
        }
        String s = new String(data, offset + 1, c);
        DNSName t = parse(data, offset + 1 + c, jumps);
        if (t.length() > 0) {
            s = s + "." + t;
        }
        return new DNSName(s);
    }

    @Override
    public int compareTo(DNSName other) {
        return ace.compareTo(other.ace);
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) return false;

        if (other instanceof DNSName) {
            DNSName otherDnsName = (DNSName) other;
            setBytesIfRequired();
            otherDnsName.setBytesIfRequired();
            return Arrays.equals(bytes, otherDnsName.bytes);
        }

        return false;
    }

    @Override
    public int hashCode() {
        if (hashCode == 0 && !isRootLabel()) {
            setBytesIfRequired();
            hashCode = Arrays.hashCode(bytes);
        }
        return hashCode;
    }

    public boolean isDirectChildOf(DNSName parent) {
        setLabelsIfRequired();
        parent.setLabelsIfRequired();
        int parentLabelsCount = parent.labels.length;

        if (labels.length - 1 != parentLabelsCount)
            return false;

        for (int i = 0; i < parent.labels.length; i++) {
            if (!labels[i].equals(parent.labels[i]))
                return false;
        }

        return true;
    }

    public boolean isChildOf(DNSName parent) {
        setLabelsIfRequired();
        parent.setLabelsIfRequired();

        if (labels.length < parent.labels.length)
            return false;

        for (int i = 0; i < parent.labels.length; i++) {
            if (!labels[i].equals(parent.labels[i]))
                return false;
        }

        return true;
    }

    public int getLabelCount() {
        setLabelsIfRequired();
        return labels.length;
    }

    public DNSName stripToLabels(int labelCount) {
        setLabelsIfRequired();

        if (labelCount > labels.length) {
            throw new IllegalArgumentException();
        }

        if (labelCount == labels.length) {
            return this;
        }

        if (labelCount == 0) {
            return EMPTY;
        }

        String[] stripedLabels = new String[labelCount];
        for (int i = 0; i < labelCount; i++) {
            stripedLabels[i] = labels[i];
        }

        return new DNSName(stripedLabels);
    }

    /**
     * Return the parent of this DNS label. Will return the root label if this label itself is the root label (because there is no parent of root).
     * <p>
     * For example:
     * </p>
     * <ul>
     *  <li><code>"foo.bar.org".getParent() == "bar.org"</code></li>
     *  <li><code> ".".getParent() == "."</code></li>
     * </ul>
     * @return the parent of this DNS label.
     */
    public DNSName getParent() {
        if (isRootLabel()) return EMPTY;
        return stripToLabels(getLabelCount() - 1);
    }

    public boolean isRootLabel() {
        return ace.isEmpty() || ace.equals(".");
    }
}
