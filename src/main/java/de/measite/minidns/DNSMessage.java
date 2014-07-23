package de.measite.minidns;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * A DNS message as defined by rfc1035. The message consists of a header and
 * 4 sections: question, answer, nameserver and addition resource record
 * section.
 * A message can either be parsed ({@link DNSMessage#parse(byte[])}) or serialized
 * ({@link DNSMessage#toArray()}).
 */
public class DNSMessage {

    /**
     * Possible DNS reply codes.
     */
    public static enum RESPONSE_CODE {
        NO_ERROR(0), FORMAT_ERR(1), SERVER_FAIL(2), NX_DOMAIN(3),
        NO_IMP(4), REFUSED(5), YXDOMAIN(6), YXRRSET(7),
        NXRRSET(8), NOT_AUTH(9),NOT_ZONE(10);

        /**
         * Reverse lookup table for response codes.
         */
        private final static RESPONSE_CODE INVERSE_LUT[] = new RESPONSE_CODE[]{
            NO_ERROR, FORMAT_ERR, SERVER_FAIL, NX_DOMAIN, NO_IMP,
            REFUSED, YXDOMAIN, YXRRSET, NXRRSET, NOT_AUTH, NOT_ZONE,
            null, null, null, null, null
        };

        /**
         * The response code value.
         */
        private final byte value;

        /**
         * Create a new response code.
         * @param value The response code value.
         */
        private RESPONSE_CODE(int value) {
            this.value = (byte)value;
        }

        /**
         * Retrieve the byte value of the response code.
         * @return the response code.
         */
        public byte getValue() {
            return (byte) value;
        }

        /**
         * Retrieve the response code for a byte value.
         * @param value The byte value.
         * @return The symbolic response code or null.
         * @throws IllegalArgumentException if the value is not in the range of
         *         0..15.
         */
        public static RESPONSE_CODE getResponseCode(int value) {
            if (value < 0 || value > 15) {
                throw new IllegalArgumentException();
            }
            return INVERSE_LUT[value];
        }

    };

    /**
     * Symbolic DNS Opcode values.
     */
    public static enum OPCODE {
        QUERY(0),
        INVERSE_QUERY(1),
        STATUS(2),
        NOTIFY(4),
        UPDATE(5);

        /**
         * Lookup table for for obcode reolution.
         */
        private final static OPCODE INVERSE_LUT[] = new OPCODE[]{
            QUERY, INVERSE_QUERY, STATUS, null, NOTIFY, UPDATE, null,
            null, null, null, null, null, null, null, null
        };

        /**
         * The value of this opcode.
         */
        private final byte value;

        /**
         * Create a new opcode for a given byte value.
         * @param value The byte value of the opcode.
         */
        private OPCODE(int value) {
            this.value = (byte)value;
        }

        /**
         * Retrieve the byte value of this opcode.
         * @return The byte value of this opcode.
         */
        public byte getValue() {
            return value;
        }

        /**
         * Retrieve the symbolic name of an opcode byte.
         * @param value The byte value of the opcode.
         * @return The symbolic opcode or null.
         * @throws IllegalArgumentException If the byte value is not in the
         *         range 0..15.
         */
        public static OPCODE getOpcode(int value) {
            if (value < 0 || value > 15) {
                throw new IllegalArgumentException();
            }
            return INVERSE_LUT[value];
        }

    };

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
     * @return The current DNS message id.
     */
    public int getId() {
        return id;
    }

    /**
     * Set the current DNS message id.
     * @param id The new DNS message id.
     */
    public void setId(int id) {
        this.id = id & 0xffff;
    }

    /**
     * Get the receive timestamp if this message was created via parse.
     * This should be used to evaluate TTLs.
     * @return The receive timestamp in milliseconds.
     */
    public long getReceiveTimestamp() {
        return receiveTimestamp;
    }

    /**
     * Retrieve the query type (true or false;
     * @return True if this DNS message is a query.
     */
    public boolean isQuery() {
        return query;
    }

    /**
     * Set the query status of this message.
     * @param query The new query status.
     */
    public void setQuery(boolean query) {
        this.query = query;
    }

    /**
     * True if the DNS message is an authoritative answer.
     * @return True if this an authoritative DNS message.
     */
    public boolean isAuthoritativeAnswer() {
        return authoritativeAnswer;
    }

    /**
     * Set the authoritative answer flag.
     * @param authoritativeAnswer Tge new authoritative answer value.
     */
    public void setAuthoritativeAnswer(boolean authoritativeAnswer) {
        this.authoritativeAnswer = authoritativeAnswer;
    }

    /**
     * Retrieve the truncation status of this message. True means that the
     * client should try a tcp lookup.
     * @return True if this message was truncated.
     */
    public boolean isTruncated() {
        return truncated;
    }

    /**
     * Set the truncation bit on this DNS message.
     * @param truncated The new truncated bit status.
     */
    public void setTruncated(boolean truncated) {
        this.truncated = truncated;
    }

    /**
     * Check if this message preferes recursion.
     * @return True if recursion is desired.
     */
    public boolean isRecursionDesired() {
        return recursionDesired;
    }

    /**
     * Set the recursion desired flag on this message.
     * @param recursionDesired The new recusrion setting.
     */
    public void setRecursionDesired(boolean recursionDesired) {
        this.recursionDesired = recursionDesired;
    }

    /**
     * Retrieve the recursion available flag of this DNS message.
     * @return The recursion available flag of this message.
     */
    public boolean isRecursionAvailable() {
        return recursionAvailable;
    }

    /**
     * Set the recursion available flog from this DNS message.
     * @param recursionAvailable The new recursion available status.
     */
    public void setRecursionAvailable(boolean recursionAvailable) {
        this.recursionAvailable = recursionAvailable;
    }

    /**
     * Retrieve the authentic data flag of this message.
     * @return The authentic data flag.
     */
    public boolean isAuthenticData() {
        return authenticData;
    }

    /**
     * Set the authentic data flag on this DNS message.
     * @param authenticData The new authentic data flag value.
     */
    public void setAuthenticData(boolean authenticData) {
        this.authenticData = authenticData;
    }

    /**
     * Check if checks are disabled.
     * @return The status of the CheckDisabled flag.
     */
    public boolean isCheckDisabled() {
        return checkDisabled;
    }

    /**
     * Change the check status of this packet.
     * @param checkDisabled The new check disabled value.
     */
    public void setCheckDisabled(boolean checkDisabled) {
        this.checkDisabled = checkDisabled;
    }

    /**
     * Generate a binary dns packet out of this message.
     * @return byte[] the binary representation.
     * @throws IOException Should never happen.
     */
    public byte[] toArray() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        DataOutputStream dos = new DataOutputStream(baos);
        int header = 0;
        if (query) {
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
        dos.writeShort((short)id);
        dos.writeShort((short)header);
        if (questions == null) {
            dos.writeShort(0);
        } else {
            dos.writeShort((short)questions.length);
        }
        if (answers == null) {
            dos.writeShort(0);
        } else {
            dos.writeShort((short)answers.length);
        }
        if (nameserverRecords == null) {
            dos.writeShort(0);
        } else {
            dos.writeShort((short)nameserverRecords.length);
        }
        if (additionalResourceRecords == null) {
            dos.writeShort(0);
        } else {
            dos.writeShort((short)additionalResourceRecords.length);
        }
        for (Question question: questions) {
            dos.write(question.toByteArray());
        }
        dos.flush();
        return baos.toByteArray();
    }

    /**
     * Build a DNS Message based on a binary DNS message.
     * @param data The DNS message data.
     * @return Parsed DNSMessage message.
     * @throws IOException On read errors.
     */
    public static DNSMessage parse(byte data[]) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(bis);
        DNSMessage message = new DNSMessage();
        message.id = dis.readUnsignedShort();
        int header = dis.readUnsignedShort();
        message.query = ((header >> 15) & 1) == 0;
        message.opcode = OPCODE.getOpcode((header >> 11) & 0xf);
        message.authoritativeAnswer = ((header >> 10) & 1) == 1;
        message.truncated = ((header >> 9) & 1) == 1;
        message.recursionDesired = ((header >> 8) & 1) == 1;
        message.recursionAvailable = ((header >> 7) & 1) == 1;
        message.authenticData = ((header >> 5) & 1) == 1;
        message.checkDisabled = ((header >> 4) & 1) == 1;
        message.responseCode = RESPONSE_CODE.getResponseCode(header & 0xf);
        message.receiveTimestamp = System.currentTimeMillis();
        int questionCount = dis.readUnsignedShort();
        int answerCount = dis.readUnsignedShort();
        int nameserverCount = dis.readUnsignedShort();
        int additionalResourceRecordCount = dis.readUnsignedShort();
        message.questions = new Question[questionCount];
        while (questionCount-- > 0) {
            Question q = Question.parse(dis, data);
            message.questions[questionCount] = q;
        }
        message.answers = new Record[answerCount];
        while (answerCount-- > 0) {
            Record rr = new Record();
            rr.parse(dis, data);
            message.answers[answerCount] = rr;
        }
        message.nameserverRecords = new Record[nameserverCount];
        while (nameserverCount-- > 0) {
            Record rr = new Record();
            rr.parse(dis, data);
            message.nameserverRecords[nameserverCount] = rr;
        }
        message.additionalResourceRecords =
                                    new Record[additionalResourceRecordCount];
        while (additionalResourceRecordCount-- > 0) {
            Record rr = new Record();
            rr.parse(dis, data);
            message.additionalResourceRecords[additionalResourceRecordCount] =
                    rr;
        }
        return message;
    }

    /**
     * Set the question part of this message.
     * @param questions The questions.
     */
    public void setQuestions(Question ... questions) {
        this.questions = questions;
    }

    /**
     * Retrieve the opcode of this message.
     * @return The opcode of this message.
     */
    public OPCODE getOpcode() {
        return opcode;
    }

    /**
     * Retrieve the response code of this message.
     * @return The response code.
     */
    public RESPONSE_CODE getResponseCode() {
        return responseCode;
    }

    /**
     * Retrieve the question section of this message.
     * @return The DNS question section.
     */
    public Question[] getQuestions() {
        return questions;
    }

    /**
     * Retrieve the answer records of this DNS message.
     * @return The answer section of this DNS message.
     */
    public Record[] getAnswers() {
        return answers;
    }

    /**
     * Retrieve the nameserver records of this DNS message.
     * @return The nameserver section of this DNS message.
     */
    public Record[] getNameserverRecords() {
        return nameserverRecords;
    }

    /**
     * Retrieve the additional resource records attached to this DNS message.
     * @return The additional resource record section of this DNS message.
     */
    public Record[] getAdditionalResourceRecords() {
        return additionalResourceRecords;
    }

    public String toString() {
        return "-- DNSMessage " + id + " --\n" +
               "Q" + Arrays.toString(questions) +
               "NS" + Arrays.toString(nameserverRecords) +
               "A" + Arrays.toString(answers) +
               "ARR" + Arrays.toString(additionalResourceRecords);
    }

}
