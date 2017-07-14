/*
 * Copyright 2015-2017 the original author or authors
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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;

import de.measite.minidns.idna.MiniDnsIdna;

/**
 * A DNS name, also called "domain name". A DNS name consists of multiple 'labels' and is subject to certain restrictions (see
 * for example <a href="https://tools.ietf.org/html/rfc3696#section-2">RFC 3696 § 2.</a>).
 * <p>
 * Instances of this class can be created by using {@link #from(String)}.
 * </p>
 *
 * @see <a href="https://tools.ietf.org/html/rfc3696">RFC 3696</a>
 * @author Florian Schmaus
 *
 */
public class DNSName implements CharSequence, Serializable, Comparable<DNSName> {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    /**
     * @see <a href="https://www.ietf.org/rfc/rfc3490.txt">RFC 3490 § 3.1 1.</a>
     */
    private static final String LABEL_SEP_REGEX = "[.\u3002\uFF0E\uFF61]";

    /**
     * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035 § 2.3.4.</a<
     */
    static final int MAX_DNSNAME_LENGTH_IN_OCTETS = 255;

    /**
     * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035 § 2.3.4.</a<
     */
    static final int MAX_LABEL_LENGTH_IN_OCTETS = 63;

    public static final int MAX_LABELS = 128;

    public static final DNSName ROOT = new DNSName(".", false);

    public static final DNSName IN_ADDR_ARPA = new DNSName("in-addr.arpa", false);

    public static final DNSName IP6_ARPA = new DNSName("ip6.arpa", false);

    /**
     * Whether or not the DNS name is validated on construction.
     */
    public static boolean VALIDATE = true;

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
        this(name, true);
    }

    private DNSName(String name, boolean inAce) {
        if (name.isEmpty()) {
            ace = ROOT.ace;
        } else if (inAce) {
            // Name is already in ACE format, just do some minor sanitation.
            ace = name.toLowerCase(Locale.US);
        } else {
            ace = MiniDnsIdna.toASCII(name);
        }

        if (!VALIDATE) {
            return;
        }

        // Validate the DNS name.
        validateMaxDnsnameLengthInOctets(name);

        setLabelsIfRequired();
        validateMaxLabelLength();
    }

    private DNSName(String[] labels, boolean validateMaxDnsnameLength, boolean validateMaxLabelLength) {
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

        if (validateMaxLabelLength) {
            validateMaxLabelLength();
        }

        if (!validateMaxDnsnameLength || !VALIDATE) {
            return;
        }

        validateMaxDnsnameLengthInOctets(ace);
    }

    private void validateMaxLabelLength() {
        for (String label : labels) {
            if (label.length() <= MAX_LABEL_LENGTH_IN_OCTETS)
                continue;

            throw new InvalidDNSNameException.LabelTooLongException(ace, label);
        }
    }

    private void validateMaxDnsnameLengthInOctets(String name) {
        setBytesIfRequired();
        if (bytes.length > MAX_DNSNAME_LENGTH_IN_OCTETS) {
            throw new InvalidDNSNameException.DNSNameTooLongException(name, bytes);
        }
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

        assert (baos.size() <= MAX_DNSNAME_LENGTH_IN_OCTETS);

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

        idn = MiniDnsIdna.toUnicode(ace);
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
        return new DNSName(name, false);
    }

    /**
     * Create a DNS name by "concatenating" the child under the parent name. The child can also be seen as the "left"
     * part of the resulting DNS name and the parent is the "right" part.
     * <p>
     * For example using "i.am.the.child" as child and "of.this.parent.example" as parent, will result in a DNS name:
     * "i.am.the.child.of.this.parent.example".
     * </p>
     *
     * @param child the child DNS name.
     * @param parent the parent DNS name.
     * @return the resulting of DNS name.
     */
    public static DNSName from(DNSName child, DNSName parent) {
        child.setLabelsIfRequired();
        parent.setLabelsIfRequired();

        String[] labels = new String[child.labels.length + parent.labels.length];
        System.arraycopy(parent.labels, 0, labels, 0, parent.labels.length);
        System.arraycopy(child.labels, 0, labels, parent.labels.length, child.labels.length);
        return new DNSName(labels, true, false);
    }

    public static DNSName from(DNSName... nameComponents) {
        int labelCount = 0;
        for (DNSName component : nameComponents) {
            component.setLabelsIfRequired();
            labelCount += component.labels.length;
        }

        String[] labels = new String[labelCount];
        int destLabelPos = 0;
        for (int i = nameComponents.length - 1; i >= 0; i--) {
            DNSName component = nameComponents[i];
            System.arraycopy(component.labels, 0, labels, destLabelPos, component.labels.length);
            destLabelPos += component.labels.length;
        }

        return new DNSName(labels, true, false);
    }

    public static DNSName from(String[] parts) {
        String[] labels = new String[parts.length];
        for (int i = 0; i < parts.length; i++) {
            labels[i] = MiniDnsIdna.toASCII(parts[i]);
        }

        return new DNSName(labels, true, true);
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
            return DNSName.ROOT;
        }
        byte b[] = new byte[c];
        dis.readFully(b);

        String childLabelString = new String(b);
        DNSName child = new DNSName(childLabelString);

        DNSName parent = parse(dis, data);
        return DNSName.from(child, parent);
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
            return DNSName.ROOT;
        }

        String childLabelString = new String(data, offset + 1, c);
        DNSName child = new DNSName(childLabelString);

        DNSName parent = parse(data, offset + 1 + c, jumps);
        return DNSName.from(child, parent);
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
            return ROOT;
        }

        String[] stripedLabels = Arrays.copyOfRange(labels, 0, labelCount);

        return new DNSName(stripedLabels, false, false);
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
        if (isRootLabel()) return ROOT;
        return stripToLabels(getLabelCount() - 1);
    }

    public boolean isRootLabel() {
        return ace.isEmpty() || ace.equals(".");
    }
}
