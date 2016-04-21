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
package de.measite.minidns;

import de.measite.minidns.record.Data;
import de.measite.minidns.record.OPT;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
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
    protected int id;

    /**
     * The DNS message opcode.
     */
    protected OPCODE opcode;

    /**
     * The response code of this dns message.
     */
    protected RESPONSE_CODE responseCode;

    /**
     * True if this is a query.
     */
    protected boolean query;

    /**
     * True if this is a authorative response.
     */
    protected boolean authoritativeAnswer;

    /**
     * True on truncate, tcp should be used.
     */
    protected boolean truncated;

    /**
     * True if the server should recurse.
     */
    protected boolean recursionDesired;

    /**
     * True if recursion is possible.
     */
    protected boolean recursionAvailable;

    /**
     * True if the server regarded the response as authentic.
     */
    protected boolean authenticData;

    /**
     * True if the server should not check the replies.
     */
    protected boolean checkDisabled;

    /**
     * The question section content.
     */
    protected Question questions[];

    /**
     * The answers section content.
     */
    protected Record answers[];

    /**
     * The nameserver records.
     */
    protected Record nameserverRecords[];

    /**
     * Additional resousrce records.
     */
    protected Record additionalResourceRecords[];

    /**
     * The receive timestamp of this message.
     */
    protected long receiveTimestamp;

    /**
     * Retrieve the current DNS message id.
     *
     * @return The current DNS message id.
     */
    public int getId() {
        return id;
    }

    /**
     * Set the current DNS message id.
     *
     * @param id The new DNS message id.
     */
    public void setId(int id) {
        this.id = id & 0xffff;
    }

    /**
     * Get the receive timestamp if this message was created via parse.
     * This should be used to evaluate TTLs.
     *
     * @return The receive timestamp in milliseconds.
     */
    public long getReceiveTimestamp() {
        return receiveTimestamp;
    }

    /**
     * Retrieve the query type (true or false).
     *
     * @return True if this DNS message is a query.
     */
    public boolean isQuery() {
        return query;
    }

    /**
     * Set the query status of this message.
     *
     * @param query The new query status.
     */
    public void setQuery(boolean query) {
        this.query = query;
    }

    /**
     * True if the DNS message is an authoritative answer.
     *
     * @return True if this an authoritative DNS message.
     */
    public boolean isAuthoritativeAnswer() {
        return authoritativeAnswer;
    }

    /**
     * Set the authoritative answer flag.
     *
     * @param authoritativeAnswer Tge new authoritative answer value.
     */
    public void setAuthoritativeAnswer(boolean authoritativeAnswer) {
        this.authoritativeAnswer = authoritativeAnswer;
    }

    /**
     * Retrieve the truncation status of this message. True means that the
     * client should try a tcp lookup.
     *
     * @return True if this message was truncated.
     */
    public boolean isTruncated() {
        return truncated;
    }

    /**
     * Set the truncation bit on this DNS message.
     *
     * @param truncated The new truncated bit status.
     */
    public void setTruncated(boolean truncated) {
        this.truncated = truncated;
    }

    /**
     * Check if this message preferes recursion.
     *
     * @return True if recursion is desired.
     */
    public boolean isRecursionDesired() {
        return recursionDesired;
    }

    /**
     * Set the recursion desired flag on this message.
     *
     * @param recursionDesired The new recusrion setting.
     */
    public void setRecursionDesired(boolean recursionDesired) {
        this.recursionDesired = recursionDesired;
    }

    /**
     * Retrieve the recursion available flag of this DNS message.
     *
     * @return The recursion available flag of this message.
     */
    public boolean isRecursionAvailable() {
        return recursionAvailable;
    }

    /**
     * Set the recursion available flog from this DNS message.
     *
     * @param recursionAvailable The new recursion available status.
     */
    public void setRecursionAvailable(boolean recursionAvailable) {
        this.recursionAvailable = recursionAvailable;
    }

    /**
     * Retrieve the authentic data flag of this message.
     *
     * @return The authentic data flag.
     */
    public boolean isAuthenticData() {
        return authenticData;
    }

    /**
     * Set the authentic data flag on this DNS message.
     *
     * @param authenticData The new authentic data flag value.
     */
    public void setAuthenticData(boolean authenticData) {
        this.authenticData = authenticData;
    }

    /**
     * Check if checks are disabled.
     *
     * @return The status of the CheckDisabled flag.
     */
    public boolean isCheckDisabled() {
        return checkDisabled;
    }

    /**
     * Change the check status of this packet.
     *
     * @param checkDisabled The new check disabled value.
     */
    public void setCheckDisabled(boolean checkDisabled) {
        this.checkDisabled = checkDisabled;
    }

    /**
     * Generate a binary dns packet out of this message.
     *
     * @return byte[] the binary representation.
     * @throws IOException Should never happen.
     */
    public byte[] toArray() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        DataOutputStream dos = new DataOutputStream(baos);
        int header = calculateHeaderBitmap();
        dos.writeShort((short) id);
        dos.writeShort((short) header);
        if (questions == null) {
            dos.writeShort(0);
        } else {
            dos.writeShort((short) questions.length);
        }
        if (answers == null) {
            dos.writeShort(0);
        } else {
            dos.writeShort((short) answers.length);
        }
        if (nameserverRecords == null) {
            dos.writeShort(0);
        } else {
            dos.writeShort((short) nameserverRecords.length);
        }
        if (additionalResourceRecords == null) {
            dos.writeShort(0);
        } else {
            dos.writeShort((short) additionalResourceRecords.length);
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
        return baos.toByteArray();
    }

    public DNSMessage() {
        query = true;
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
        query = ((header >> 15) & 1) == 0;
        opcode = OPCODE.getOpcode((header >> 11) & 0xf);
        authoritativeAnswer = ((header >> 10) & 1) == 1;
        truncated = ((header >> 9) & 1) == 1;
        recursionDesired = ((header >> 8) & 1) == 1;
        recursionAvailable = ((header >> 7) & 1) == 1;
        authenticData = ((header >> 5) & 1) == 1;
        checkDisabled = ((header >> 4) & 1) == 1;
        responseCode = RESPONSE_CODE.getResponseCode(header & 0xf);
        receiveTimestamp = System.currentTimeMillis();
        int questionCount = dis.readUnsignedShort();
        int answerCount = dis.readUnsignedShort();
        int nameserverCount = dis.readUnsignedShort();
        int additionalResourceRecordCount = dis.readUnsignedShort();
        questions = new Question[questionCount];
        for (int i = 0; i < questionCount; i++) {
            questions[i] = new Question(dis, data);
        }
        answers = new Record[answerCount];
        for (int i = 0; i < answerCount; i++) {
            answers[i] = new Record(dis, data);
        }
        nameserverRecords = new Record[nameserverCount];
        for (int i = 0; i < nameserverCount; i++) {
            nameserverRecords[i] = new Record(dis, data);
        }
        additionalResourceRecords = new Record[additionalResourceRecordCount];
        for (int i = 0; i < additionalResourceRecordCount; i++) {
            additionalResourceRecords[i] = new Record(dis, data);
        }
    }

    public DNSMessage(DNSMessage copy) {
        id = copy.id;
        query = copy.query;
        opcode = copy.opcode;
        authoritativeAnswer = copy.authoritativeAnswer;
        truncated = copy.truncated;
        recursionDesired = copy.recursionDesired;
        recursionAvailable = copy.recursionAvailable;
        authenticData = copy.authenticData;
        checkDisabled = copy.checkDisabled;
        responseCode = copy.responseCode;
        receiveTimestamp = copy.receiveTimestamp;
        questions = copy.questions;
        answers = copy.answers == null ? new Record[0] : copy.answers;
        nameserverRecords = copy.nameserverRecords == null ? new Record[0] : copy.nameserverRecords;
        additionalResourceRecords = copy.additionalResourceRecords == null ? new Record[0] : copy.additionalResourceRecords;
    }

    public DNSMessage(DNSMessage copy, Record[] answers, Record[] nameserverRecords, Record[] additionalResourceRecords) {
        this(copy);
        this.answers = answers == null ? new Record[0] : answers;
        this.nameserverRecords = nameserverRecords == null ? new Record[0] : nameserverRecords;
        this.additionalResourceRecords = additionalResourceRecords == null ? new Record[0] : additionalResourceRecords;
    }

    int calculateHeaderBitmap() {
        int header = 0;
        if (!query) {
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
        if (checkDisabled) {
            header += 1 << 4;
        }
        if (responseCode != null) {
            header += responseCode.getValue();
        }
        return header;
    }

    /**
     * Set the question part of this message.
     *
     * @param questions The questions.
     */
    public void setQuestions(Question... questions) {
        this.questions = questions;
    }

    /**
     * Retrieve the opcode of this message.
     *
     * @return The opcode of this message.
     */
    public OPCODE getOpcode() {
        return opcode;
    }

    /**
     * Retrieve the response code of this message.
     *
     * @return The response code.
     */
    public RESPONSE_CODE getResponseCode() {
        return responseCode;
    }

    /**
     * Retrieve the question section of this message.
     *
     * @return The DNS question section.
     */
    public Question[] getQuestions() {
        return questions;
    }

    /**
     * Retrieve the answer records of this DNS message.
     *
     * @return The answer section of this DNS message.
     */
    public Record[] getAnswers() {
        return answers;
    }

    /**
     * Retrieve the nameserver records of this DNS message.
     *
     * @return The nameserver section of this DNS message.
     */
    public Record[] getNameserverRecords() {
        return nameserverRecords;
    }

    /**
     * Retrieve the additional resource records attached to this DNS message.
     *
     * @return The additional resource record section of this DNS message.
     */
    public Record[] getAdditionalResourceRecords() {
        return additionalResourceRecords;
    }

    /**
     * Send the OPT pseudo record with this request for EDNS support. The OPT record
     * can be used to announce the supported size of UDP payload as well as additional
     * flags.
     *
     * Note that some networks and firewalls are known to block big UDP payloads.
     * 1280 should be a reasonable value, everything below 512 is treated as 512 and
     * should work on all networks.
     *
     * @param udpPayloadSize Supported size of payload. Must be between 512 and 65563.
     * @param optFlags       A bitmap of flags to be attached to the
     */
    public void setOptPseudoRecord(int udpPayloadSize, int optFlags) {
        Record opt = OPT.createEdnsOptRecord(udpPayloadSize, optFlags);
        if (additionalResourceRecords == null) {
            additionalResourceRecords = new Record[]{opt};
        } else {
            ArrayList<Record> records = new ArrayList<Record>(Arrays.asList(additionalResourceRecords));
            for (Iterator<Record> iterator = records.iterator(); iterator.hasNext(); ) {
                Record record = iterator.next();
                if (record.type == Record.TYPE.OPT) {
                    iterator.remove();
                }
            }
            records.add(opt);
            additionalResourceRecords = records.toArray(new Record[records.size()]);
        }
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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("DNSMessage")
                .append('(').append(id).append(' ')
                .append(opcode).append(' ')
                .append(responseCode);
        if (!query) sb.append(" qr");
        if (authoritativeAnswer) sb.append(" aa");
        if (truncated) sb.append(" tr");
        if (recursionDesired) sb.append(" rd");
        if (recursionAvailable) sb.append(" ra");
        if (authenticData) sb.append(" ad");
        if (checkDisabled) sb.append(" cd");
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

        return sb.toString();
    }

    /**
     * Format the DNSMessage object in a way suitable for terminal output.
     * The format is loosely based on the output provided by {@code dig}.
     *
     * @return This message as a String suitable for terminal output.
     */
    public String asTerminalOutput() {
        StringBuilder sb = new StringBuilder(";; ->>HEADER<<-")
                .append(" opcode: ").append(opcode)
                .append(", status: ").append(responseCode)
                .append(", id: ").append(id).append("\n")
                .append(";; flags:");
        if (!query) sb.append(" qr");
        if (authoritativeAnswer) sb.append(" aa");
        if (truncated) sb.append(" tr");
        if (recursionDesired) sb.append(" rd");
        if (recursionAvailable) sb.append(" ra");
        if (authenticData) sb.append(" ad");
        if (checkDisabled) sb.append(" cd");
        sb.append("; QUERY: ").append(questions == null ? 0 : questions.length)
                .append(", ANSWER: ").append(answers == null ? 0 : answers.length)
                .append(", AUTHORITY: ").append(nameserverRecords == null ? 0 : nameserverRecords.length)
                .append(", ADDITIONAL: ").append(additionalResourceRecords == null ? 0 : additionalResourceRecords.length)
                .append("\n\n");
        if (additionalResourceRecords != null && additionalResourceRecords.length != 0) {
            for (Record record : additionalResourceRecords) {
                if (record.type == Record.TYPE.OPT) {
                    sb.append(";; OPT PSEUDOSECTION:\n; ").append(OPT.optRecordToString(record)).append("\n");
                }
            }
        }
        if (questions != null && questions.length != 0) {
            sb.append(";; QUESTION SECTION:\n");
            for (Question question : questions) {
                sb.append(';').append(question.toString()).append('\n');
            }
        }
        if (nameserverRecords != null && nameserverRecords.length != 0) {
            sb.append("\n;; AUTHORITY SECTION:\n");
            for (Record record : nameserverRecords) {
                sb.append(record.toString()).append('\n');
            }
        }
        if (answers != null && answers.length != 0) {
            sb.append("\n;; ANSWER SECTION:\n");
            for (Record record : answers) {
                sb.append(record.toString()).append('\n');
            }
        }
        if (additionalResourceRecords != null && additionalResourceRecords.length != 0) {
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
        return sb.append("\n;; WHEN: ").append(new Date(receiveTimestamp).toString()).toString();
    }

    public <D extends Data> Set<D> getAnswersFor(Question q) {
        if (responseCode != RESPONSE_CODE.NO_ERROR) return null;

        // It would be great if we could verify that D matches q.type at this
        // point. But on the other hand, if it does not, then the cast to D
        // below will fail.
        Set<D> res = new HashSet<>(answers.length);
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
}
