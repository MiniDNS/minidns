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

import de.measite.minidns.record.Data;
import de.measite.minidns.record.OPT;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A DNS message as defined by RFC 1035. The message consists of a header and
 * 4 sections: question, answer, nameserver and addition resource record
 * section.
 * A message can either be parsed ({@link #DNSMessage(byte[])}) or serialized
 * ({@link DNSMessage#toArray()}).
 * 
 * @see <a href="https://www.ietf.org/rfc/rfc1035.txt">RFC 1035</a>
 */
public class DNSMessage {

    private static final Logger LOGGER = Logger.getLogger(DNSMessage.class.getName());

    /**
     * Possible DNS response codes.
     * 
     * @see <a href=
     *      "http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6">
     *      IANA Domain Name System (DNS) Paramters - DNS RCODEs</a>
     * @see <a href="http://tools.ietf.org/html/rfc6895#section-2.3">RFC 6895 § 2.3</a>
     */
    public static enum RESPONSE_CODE {
        NO_ERROR(0),
        FORMAT_ERR(1),
        SERVER_FAIL(2),
        NX_DOMAIN(3),
        NO_IMP(4),
        REFUSED(5),
        YXDOMAIN(6),
        YXRRSET(7),
        NXRRSET(8),
        NOT_AUTH(9),
        NOT_ZONE(10),
        BADVERS_BADSIG(16),
        BADKEY(17),
        BADTIME(18),
        BADMODE(19),
        BADNAME(20),
        BADALG(21),
        BADTRUNC(22),
        BADCOOKIE(23),
        ;

        /**
         * Reverse lookup table for response codes.
         */
        private final static Map<Integer, RESPONSE_CODE> INVERSE_LUT = new HashMap<>(RESPONSE_CODE.values().length);

        static {
            for (RESPONSE_CODE responseCode : RESPONSE_CODE.values()) {
                INVERSE_LUT.put((int) responseCode.value, responseCode);
            }
        }

        /**
         * The response code value.
         */
        private final byte value;

        /**
         * Create a new response code.
         *
         * @param value The response code value.
         */
        private RESPONSE_CODE(int value) {
            this.value = (byte) value;
        }

        /**
         * Retrieve the byte value of the response code.
         *
         * @return the response code.
         */
        public byte getValue() {
            return value;
        }

        /**
         * Retrieve the response code for a byte value.
         *
         * @param value The byte value.
         * @return The symbolic response code or null.
         * @throws IllegalArgumentException if the value is not in the range of 0..15.
         */
        public static RESPONSE_CODE getResponseCode(int value) throws IllegalArgumentException {
            if (value < 0 || value > 65535) {
                throw new IllegalArgumentException();
            }
            return INVERSE_LUT.get(value);
        }

    }

    /**
     * Symbolic DNS Opcode values.
     * 
     * @see <a href=
     *      "http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5">
     *      IANA Domain Name System (DNS) Paramters - DNS OpCodes</a>
     */
    public static enum OPCODE {
        QUERY,
        INVERSE_QUERY,
        STATUS,
        UNASSIGNED3,
        NOTIFY,
        UPDATE,
        ;

        /**
         * Lookup table for for opcode resolution.
         */
        private final static OPCODE INVERSE_LUT[] = new OPCODE[OPCODE.values().length];

        static {
            for (OPCODE opcode : OPCODE.values()) {
                if (INVERSE_LUT[opcode.getValue()] != null) {
                    throw new IllegalStateException();
                }
                INVERSE_LUT[opcode.getValue()] = opcode;
            }
        }

        /**
         * The value of this opcode.
         */
        private final byte value;

        /**
         * Create a new opcode for a given byte value.
         *
         */
        private OPCODE() {
            this.value = (byte) this.ordinal();
        }

        /**
         * Retrieve the byte value of this opcode.
         *
         * @return The byte value of this opcode.
         */
        public byte getValue() {
            return value;
        }

        /**
         * Retrieve the symbolic name of an opcode byte.
         *
         * @param value The byte value of the opcode.
         * @return The symbolic opcode or null.
         * @throws IllegalArgumentException If the byte value is not in the
         *                                  range 0..15.
         */
        public static OPCODE getOpcode(int value) throws IllegalArgumentException {
            if (value < 0 || value > 15) {
                throw new IllegalArgumentException();
            }
            if (value >= INVERSE_LUT.length) {
                return null;
            }
            return INVERSE_LUT[value];
        }

    }

    /**
     * The DNS message id.
     */
    public final int id;

    /**
     * The DNS message opcode.
     */
    public final OPCODE opcode;

    /**
     * The response code of this dns message.
     */
    public final RESPONSE_CODE responseCode;

    /**
     * The QR flag of the DNS message header. Note that this will be <code>true</code> if the message is a
     * <b>response</b> and <code>false</code> if it is a <b>query</b>.
     * 
     * @see <a href="https://www.ietf.org/rfc/rfc1035.txt">RFC 1035 § 4.1.1</a>
     */
    public final boolean qr;

    /**
     * True if this is a authorative response.
     */
    public final boolean authoritativeAnswer;

    /**
     * True if message is truncated. Then TCP should be used.
     */
    public final boolean truncated;

    /**
     * True if the server should recurse.
     */
    public final boolean recursionDesired;

    /**
     * True if recursion is possible.
     */
    public final boolean recursionAvailable;

    /**
     * True if the server regarded the response as authentic.
     */
    public final boolean authenticData;

    /**
     * True if the server should not perform DNSSEC validation before returning the result.
     */
    public final boolean checkingDisabled;

    /**
     * The question section content.
     */
    public final List<Question> questions;

    /**
     * The answers section content.
     */
    public final List<Record> answers;

    /**
     * The nameserver records.
     */
    public final List<Record> nameserverRecords;

    /**
     * Additional resource records.
     */
    public final List<Record> additionalResourceRecords;

    /**
     * The receive timestamp. Set only if this message was created via parse.
     * This should be used to evaluate TTLs.
     */
    public final long receiveTimestamp;

    protected DNSMessage(Builder builder) {
        this.id = builder.id;
        this.opcode = builder.opcode;
        this.responseCode = builder.responseCode;
        this.receiveTimestamp = builder.receiveTimestamp;
        this.qr = builder.query;
        this.authoritativeAnswer = builder.authoritativeAnswer;
        this.truncated = builder.truncated;
        this.recursionDesired = builder.recursionDesired;
        this.recursionAvailable = builder.recursionAvailable;
        this.authenticData = builder.authenticData;
        this.checkingDisabled = builder.checkingDisabled;

        if (builder.questions == null) {
            this.questions = Collections.emptyList();
        } else {
            List<Question> q = new ArrayList<>(builder.questions.size());
            q.addAll(builder.questions);
            this.questions = Collections.unmodifiableList(q);
        }

        if (builder.answers == null) {
            this.answers = Collections.emptyList();
        } else {
            List<Record> a = new ArrayList<>(builder.answers.size());
            a.addAll(builder.answers);
            this.answers = Collections.unmodifiableList(a);
        }

        if (builder.nameserverRecords == null) {
            this.nameserverRecords = Collections.emptyList();
        } else {
            List<Record> n = new ArrayList<>(builder.nameserverRecords.size());
            n.addAll(builder.nameserverRecords);
            this.nameserverRecords = Collections.unmodifiableList(n);
        }

        if (builder.additionalResourceRecords == null) {
            this.additionalResourceRecords = Collections.emptyList();
        } else {
            List<Record> a = new ArrayList<>(builder.additionalResourceRecords.size());
            a.addAll(builder.additionalResourceRecords);
            this.additionalResourceRecords = Collections.unmodifiableList(a);
        }

        // TODO Add verification of dns message state here
    }

    /**
     * Build a DNS Message based on a binary DNS message.
     *
     * @param data The DNS message data.
     * @throws IOException On read errors.
     */
    public DNSMessage(byte data[]) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(bis);
        id = dis.readUnsignedShort();
        int header = dis.readUnsignedShort();
        qr = ((header >> 15) & 1) == 1;
        opcode = OPCODE.getOpcode((header >> 11) & 0xf);
        authoritativeAnswer = ((header >> 10) & 1) == 1;
        truncated = ((header >> 9) & 1) == 1;
        recursionDesired = ((header >> 8) & 1) == 1;
        recursionAvailable = ((header >> 7) & 1) == 1;
        authenticData = ((header >> 5) & 1) == 1;
        checkingDisabled = ((header >> 4) & 1) == 1;
        responseCode = RESPONSE_CODE.getResponseCode(header & 0xf);
        receiveTimestamp = System.currentTimeMillis();
        int questionCount = dis.readUnsignedShort();
        int answerCount = dis.readUnsignedShort();
        int nameserverCount = dis.readUnsignedShort();
        int additionalResourceRecordCount = dis.readUnsignedShort();
        questions = new ArrayList<>(questionCount);
        for (int i = 0; i < questionCount; i++) {
            questions.add(new Question(dis, data));
        }
        answers = new ArrayList<>(answerCount);
        for (int i = 0; i < answerCount; i++) {
            answers.add(new Record(dis, data));
        }
        nameserverRecords = new ArrayList<>(nameserverCount);
        for (int i = 0; i < nameserverCount; i++) {
            nameserverRecords.add(new Record(dis, data));
        }
        additionalResourceRecords = new ArrayList<>(additionalResourceRecordCount);
        for (int i = 0; i < additionalResourceRecordCount; i++) {
            additionalResourceRecords.add(new Record(dis, data));
        }
    }

    /**
     * Constructs an normalized version of the given DNSMessage by setting the id to '0'.
     *
     * @param message the message of which normalized version should be constructed.
     */
    private DNSMessage(DNSMessage message) {
        id = 0;
        qr = message.qr;
        opcode = message.opcode;
        authoritativeAnswer = message.authoritativeAnswer;
        truncated = message.truncated;
        recursionDesired = message.recursionDesired;
        recursionAvailable = message.recursionAvailable;
        authenticData = message.authenticData;
        checkingDisabled = message.checkingDisabled;
        responseCode = message.responseCode;
        receiveTimestamp = message.receiveTimestamp;
        questions = message.questions;
        answers = message.answers;
        nameserverRecords = message.nameserverRecords;
        additionalResourceRecords = message.additionalResourceRecords;
    }


    /**
     * Generate a binary dns packet out of this message.
     *
     * @return byte[] the binary representation.
     * @throws IOException Should never happen.
     */
    public byte[] toArray() throws IOException {
        return serialize().clone();
    }

    public DatagramPacket asDatagram(InetAddress address, int port) {
        byte[] bytes = serialize();
        return new DatagramPacket(bytes, bytes.length, address, port);
    }

    public void writeTo(DataOutputStream dataOutputStream) throws IOException {
        byte[] bytes = serialize();
        dataOutputStream.writeShort(bytes.length);
        dataOutputStream.write(bytes);
    }

    private byte[] byteCache;

    private byte[] serialize() {
        if (byteCache != null) {
            return byteCache;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        DataOutputStream dos = new DataOutputStream(baos);
        int header = calculateHeaderBitmap();
        try {
            dos.writeShort((short) id);
            dos.writeShort((short) header);
            if (questions == null) {
                dos.writeShort(0);
            } else {
                dos.writeShort((short) questions.size());
            }
            if (answers == null) {
                dos.writeShort(0);
            } else {
                dos.writeShort((short) answers.size());
            }
            if (nameserverRecords == null) {
                dos.writeShort(0);
            } else {
                dos.writeShort((short) nameserverRecords.size());
            }
            if (additionalResourceRecords == null) {
                dos.writeShort(0);
            } else {
                dos.writeShort((short) additionalResourceRecords.size());
            }
            if (questions != null) {
                for (Question question : questions) {
                    dos.write(question.toByteArray());
                }
            }
            if (answers != null) {
                for (Record answer : answers) {
                    dos.write(answer.toByteArray());
                }
            }
            if (nameserverRecords != null) {
                for (Record nameserverRecord : nameserverRecords) {
                    dos.write(nameserverRecord.toByteArray());
                }
            }
            if (additionalResourceRecords != null) {
                for (Record additionalResourceRecord : additionalResourceRecords) {
                    dos.write(additionalResourceRecord.toByteArray());
                }
            }
            dos.flush();
        } catch (IOException e) {
            // Should never happen.
            throw new AssertionError(e);
        }
        byteCache = baos.toByteArray();
        return byteCache;
    }

    int calculateHeaderBitmap() {
        int header = 0;
        if (qr) {
            header += 1 << 15;
        }
        if (opcode != null) {
            header += opcode.getValue() << 11;
        }
        if (authoritativeAnswer) {
            header += 1 << 10;
        }
        if (truncated) {
            header += 1 << 9;
        }
        if (recursionDesired) {
            header += 1 << 8;
        }
        if (recursionAvailable) {
            header += 1 << 7;
        }
        if (authenticData) {
            header += 1 << 5;
        }
        if (checkingDisabled) {
            header += 1 << 4;
        }
        if (responseCode != null) {
            header += responseCode.getValue();
        }
        return header;
    }

    public Question getQuestion() {
        return questions.get(0);
    }

    public List<Question> copyQuestions() {
        List<Question> copy = new ArrayList<>(questions.size());
        copy.addAll(questions);
        return copy;
    }

    public List<Record> copyAnswers() {
        List<Record> res = new ArrayList<>(answers.size());
        res.addAll(answers);
        return res;
    }

    public List<Record> copyNameserverRecords() {
        List<Record> res = new ArrayList<>(nameserverRecords.size());
        res.addAll(nameserverRecords);
        return res;
    }

    /**
     * Check if the EDNS DO (DNSSEC OK) flag is set.
     *
     * @return true if the DO flag is set.
     */
    public boolean isDnssecOk() {
        if (additionalResourceRecords == null)
            return false;

        for (Record record : additionalResourceRecords) {
            if (record.type != Record.TYPE.OPT) continue;
            int ednsFlags = OPT.readEdnsFlags(record);
            return (ednsFlags & OPT.FLAG_DNSSEC_OK) > 0;
        }

        return false;
    }

    private String toStringCache;

    @Override
    public String toString() {
        if (toStringCache != null) return toStringCache;

        StringBuilder sb = new StringBuilder("DNSMessage")
                .append('(').append(id).append(' ')
                .append(opcode).append(' ')
                .append(responseCode).append(' ');
        if (qr) {
            sb.append("resp[qr=1]");
        } else {
            sb.append("query[qr=0]");
        }
        if (authoritativeAnswer) sb.append(" aa");
        if (truncated) sb.append(" tr");
        if (recursionDesired) sb.append(" rd");
        if (recursionAvailable) sb.append(" ra");
        if (authenticData) sb.append(" ad");
        if (checkingDisabled) sb.append(" cd");
        sb.append(")\n");
        if (questions != null) {
            for (Question question : questions) {
                sb.append("[Q: ").append(question).append("]\n");
            }
        }
        if (answers != null) {
            for (Record record : answers) {
                sb.append("[A: ").append(record).append("]\n");
            }
        }
        if (nameserverRecords != null) {
            for (Record record : nameserverRecords) {
                sb.append("[N: ").append(record).append("]\n");
            }
        }
        if (additionalResourceRecords != null) {
            for (Record record : additionalResourceRecords) {
                sb.append("[X: ");
                if (record.type == Record.TYPE.OPT) {
                    sb.append(OPT.optRecordToString(record));
                } else {
                    sb.append(record);
                }
                sb.append("]\n");
            }
        }

        // Strip trailing newline.
        if (sb.charAt(sb.length() - 1) == '\n') {
            sb.setLength(sb.length() - 1);
        }

        toStringCache = sb.toString();
        return toStringCache;
    }

    private String terminalOutputCache;

    /**
     * Format the DNSMessage object in a way suitable for terminal output.
     * The format is loosely based on the output provided by {@code dig}.
     *
     * @return This message as a String suitable for terminal output.
     */
    public String asTerminalOutput() {
        if (terminalOutputCache != null) return terminalOutputCache;

        StringBuilder sb = new StringBuilder(";; ->>HEADER<<-")
                .append(" opcode: ").append(opcode)
                .append(", status: ").append(responseCode)
                .append(", id: ").append(id).append("\n")
                .append(";; flags:");
        if (!qr) sb.append(" qr");
        if (authoritativeAnswer) sb.append(" aa");
        if (truncated) sb.append(" tr");
        if (recursionDesired) sb.append(" rd");
        if (recursionAvailable) sb.append(" ra");
        if (authenticData) sb.append(" ad");
        if (checkingDisabled) sb.append(" cd");
        sb.append("; QUERY: ").append(questions.size())
                .append(", ANSWER: ").append(answers.size())
                .append(", AUTHORITY: ").append(nameserverRecords.size())
                .append(", ADDITIONAL: ").append(additionalResourceRecords.size())
                .append("\n\n");
        for (Record record : additionalResourceRecords) {
            if (record.type == Record.TYPE.OPT) {
                sb.append(";; OPT PSEUDOSECTION:\n; ").append(OPT.optRecordToString(record)).append("\n");
                break;
            }
        }
        if (questions.size() != 0) {
            sb.append(";; QUESTION SECTION:\n");
            for (Question question : questions) {
                sb.append(';').append(question.toString()).append('\n');
            }
        }
        if (nameserverRecords.size() != 0) {
            sb.append("\n;; AUTHORITY SECTION:\n");
            for (Record record : nameserverRecords) {
                sb.append(record.toString()).append('\n');
            }
        }
        if (answers.size() != 0) {
            sb.append("\n;; ANSWER SECTION:\n");
            for (Record record : answers) {
                sb.append(record.toString()).append('\n');
            }
        }
        if (additionalResourceRecords.size() != 0) {
            boolean hasNonOptArr = false;
            for (Record record : additionalResourceRecords) {
                if (record.type != Record.TYPE.OPT) {
                    if (!hasNonOptArr) {
                        hasNonOptArr = true;
                        sb.append("\n;; ADDITIONAL SECTION:\n");
                    }
                    sb.append(record.toString()).append('\n');
                }
            }
        }
        if (receiveTimestamp > 0) {
            sb.append("\n;; WHEN: ").append(new Date(receiveTimestamp).toString());
        }
        terminalOutputCache = sb.toString();
        return terminalOutputCache;
    }

    public <D extends Data> Set<D> getAnswersFor(Question q) {
        if (responseCode != RESPONSE_CODE.NO_ERROR) return null;

        // It would be great if we could verify that D matches q.type at this
        // point. But on the other hand, if it does not, then the cast to D
        // below will fail.
        Set<D> res = new HashSet<>(answers.size());
        for (Record record : answers) {
            if (!record.isAnswer(q)) continue;

            Data data = record.getPayload();
            @SuppressWarnings("unchecked")
            D d = (D) data;
            boolean isNew = res.add(d);
            if (!isNew) {
                LOGGER.log(Level.WARNING, "DNSMessage contains duplicate answers. Record: " + record + "; DNSMessage: " + this);
            }
        }
        return res;
    }

    public Builder asBuilder() {
        return new Builder(this);
    }

    private DNSMessage normalizedVersionCache;

    public DNSMessage asNormalizedVersion() {
        if (normalizedVersionCache == null) {
            normalizedVersionCache = new DNSMessage(this);
        }
        return normalizedVersionCache;
    }

    private transient Integer hashCodeCache;

    @Override
    public int hashCode() {
        if (hashCodeCache == null) {
            byte[] bytes = serialize();
            hashCodeCache = Arrays.hashCode(bytes);
        }
        return hashCodeCache;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof DNSMessage)) {
            return false;
        }
        if (other == this) {
            return true;
        }
        DNSMessage otherDnsMessage = (DNSMessage) other;
        byte[] otherBytes = otherDnsMessage.serialize();
        byte[] myBytes = serialize();
        return Arrays.equals(myBytes, otherBytes);
    }

    public static Builder builder() {
        return new DNSMessage.Builder();
    }

    public static class Builder {

        private Builder() {
        }

        private Builder(DNSMessage message) {
            id = message.id;
            opcode = message.opcode;
            responseCode = message.responseCode;
            query = message.qr;
            authoritativeAnswer = message.authoritativeAnswer;
            truncated = message.truncated;
            recursionDesired = message.recursionDesired;
            recursionAvailable = message.recursionAvailable;
            authenticData = message.authenticData;
            checkingDisabled = message.checkingDisabled;
            receiveTimestamp = message.receiveTimestamp;

            // Copy the unmodifiable lists over into this new builder.
            questions = new ArrayList<>(message.questions.size());
            questions.addAll(message.questions);
            answers = new ArrayList<>(message.answers.size());
            answers.addAll(message.answers);
            nameserverRecords = new ArrayList<>(message.nameserverRecords.size());
            nameserverRecords.addAll(message.nameserverRecords);
            additionalResourceRecords = new ArrayList<>(message.additionalResourceRecords.size());
            additionalResourceRecords.addAll(message.additionalResourceRecords);
        }

        private int id;
        private OPCODE opcode = OPCODE.QUERY;
        private RESPONSE_CODE responseCode = RESPONSE_CODE.NO_ERROR;
        private boolean query;
        private boolean authoritativeAnswer;
        private boolean truncated;
        private boolean recursionDesired;
        private boolean recursionAvailable;
        private boolean authenticData;
        private boolean checkingDisabled;

        private long receiveTimestamp = -1;

        private List<Question> questions;
        private List<Record> answers;
        private List<Record> nameserverRecords;
        private List<Record> additionalResourceRecords;

        /**
         * Set the current DNS message id.
         *
         * @param id The new DNS message id.
         * @return a reference to this builder.
         */
        public Builder setId(int id) {
            this.id = id & 0xffff;
            return this;
        }

        public Builder setOpcode(OPCODE opcode) {
            this.opcode = opcode;
            return this;
        }

        public Builder setResponseCode(RESPONSE_CODE responseCode) {
            this.responseCode = responseCode;
            return this;
        }

        /**
         * Set the QR flag.
         *
         * @param query The new QR flag status.
         * @return a reference to this builder.
         */
        public Builder setQrFlag(boolean query) {
            this.query = query;
            return this;
        }

        /**
         * Set the authoritative answer flag.
         *
         * @param authoritativeAnswer Tge new authoritative answer value.
         * @return a reference to this builder.
         */
        public Builder setAuthoritativeAnswer(boolean authoritativeAnswer) {
            this.authoritativeAnswer = authoritativeAnswer;
            return this;
        }

        /**
         * Set the truncation bit on this DNS message.
         *
         * @param truncated The new truncated bit status.
         * @return a reference to this builder.
         */
        public Builder setTruncated(boolean truncated) {
            this.truncated = truncated;
            return this;
        }

        /**
         * Set the recursion desired flag on this message.
         *
         * @param recursionDesired The new recusrion setting.
         * @return a reference to this builder.
         */
        public Builder setRecursionDesired(boolean recursionDesired) {
            this.recursionDesired = recursionDesired;
            return this;
        }

        /**
         * Set the recursion available flog from this DNS message.
         *
		 * @param recursionAvailable The new recursion available status.
         * @return a reference to this builder.
         */
        public Builder setRecursionAvailable(boolean recursionAvailable) {
            this.recursionAvailable = recursionAvailable;
            return this;
        }

        /**
         * Set the authentic data flag on this DNS message.
         *
         * @param authenticData The new authentic data flag value.
         * @return a reference to this builder.
         */
        public Builder setAuthenticData(boolean authenticData) {
            this.authenticData = authenticData;
            return this;
        }

        /**
         * Change the check status of this packet.
         *
         * @param checkingDisabled The new check disabled value.
         * @return a reference to this builder.
         */
        @Deprecated
        public Builder setCheckDisabled(boolean checkingDisabled) {
            this.checkingDisabled = checkingDisabled;
            return this;
        }

        /**
         * Change the check status of this packet.
         *
         * @param checkingDisabled The new check disabled value.
         * @return a reference to this builder.
         */
        public Builder setCheckingDisabled(boolean checkingDisabled) {
            this.checkingDisabled = checkingDisabled;
            return this;
        }

        public Builder setReceiveTimestamp(long receiveTimestamp) {
            this.receiveTimestamp = receiveTimestamp;
            return this;
        }

        public Builder addQuestion(Question question) {
            if (questions == null) {
                questions = new ArrayList<>(1);
            }
            questions.add(question);
            return this;
        }

        /**
         * Set the question part of this message.
         *
         * @param questions The questions.
         * @return a reference to this builder.
         */
        public Builder setQuestions(List<Question> questions) {
            this.questions = questions;
            return this;
        }

        /**
         * Set the question part of this message.
         *
         * @param questions The questions.
         * @return a reference to this builder.
         */
        public Builder setQuestions(Question... questions) {
            this.questions = new ArrayList<>(questions.length);
            for (Question q : questions) {
                this.questions.add(q);
            }
            return this;
        }

        public Builder setQuestion(Question question) {
            this.questions = new ArrayList<>(1);
            this.questions.add(question);
            return this;
        }

        public Builder addAnswer(Record answer) {
            if (answers == null) {
                answers = new ArrayList<>(1);
            }
            answers.add(answer);
            return this;
        }

        public Builder addAnswers(Collection<Record> records) {
            if (answers == null) {
                answers = new ArrayList<>(records.size());
            }
            answers.addAll(records);
            return this;
        }

        public Builder setAnswers(Record... records) {
            answers = new ArrayList<>(records.length);
            for (Record record : records) {
                answers.add(record);
            }
            return this;
        }

        public Builder setAnswers(Collection<Record> records) {
            answers = new ArrayList<>(records.size());
            answers.addAll(records);
            return this;
        }

        public List<Record> getAnswers() {
            if (answers == null) {
                return Collections.emptyList();
            }
            return answers;
        }

        public Builder addNameserverRecords(Record record) {
            if (nameserverRecords == null) {
                nameserverRecords = new ArrayList<>(8);
            }
            nameserverRecords.add(record);
            return this;
        }

        public Builder setNameserverRecords(Collection<Record> records) {
            nameserverRecords = new ArrayList<>(records.size());
            nameserverRecords.addAll(records);
            return this;
        }

        public Builder setNameserverRecords(Record... records) {
            nameserverRecords = new ArrayList<>(records.length);
            for (Record record : records) {
                nameserverRecords.add(record);
            }
            return this;
        }

        public Builder setAdditionalResourceRecords(Collection<Record> records) {
            additionalResourceRecords = new ArrayList<>(records.size());
            additionalResourceRecords.addAll(records);
            return this;
        }

        public Builder addAdditionalResourceRecords(List<Record> records) {
            if (additionalResourceRecords == null) {
                additionalResourceRecords = new ArrayList<>(records.size());
            }
            additionalResourceRecords.addAll(records);
            return this;
        }

        public Builder addAdditionalResourceRecords(Record... records) {
            if (additionalResourceRecords == null) {
                additionalResourceRecords = new ArrayList<>(records.length);
            }
            for (Record record : records) {
                additionalResourceRecords.add(record);
            }
            return this;
        }

        public List<Record> getAdditionalResourceRecords() {
            if (additionalResourceRecords == null) {
                return Collections.emptyList();
            }
            return additionalResourceRecords;
        }

        /**
         * Send the OPT pseudo record with this request for EDNS support. The OPT record can be used
         * to announce the supported size of UDP payload as well as additional flags.
         *
         * Note that some networks and firewalls are known to block big UDP payloads. 1280 should be
         * a reasonable value, everything below 512 is treated as 512 and should work on all
         * networks.
         *
         * @param udpPayloadSize Supported size of payload. Must be between 512 and 65563.
         * @param optFlags A bitmap of flags to be attached to the
         * @return a reference to this builder.
         */
        public Builder setOptPseudoRecord(int udpPayloadSize, int optFlags) {
            Record opt = OPT.createEdnsOptRecord(udpPayloadSize, optFlags);
            if (additionalResourceRecords == null) {
                additionalResourceRecords = new ArrayList<>(4);
                additionalResourceRecords.add(opt);
            } else {
                for (Iterator<Record> iterator = additionalResourceRecords.iterator(); iterator
                        .hasNext();) {
                    Record record = iterator.next();
                    if (record.type == Record.TYPE.OPT) {
                        iterator.remove();
                    }
                }
                additionalResourceRecords.add(opt);
            }
            return this;
        }

        public DNSMessage build() {
            return new DNSMessage(this);
        }

    }

}
