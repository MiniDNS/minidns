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
package org.minidns.dnsmessage;

import org.minidns.dnsname.DnsName;
import org.minidns.record.Record.CLASS;
import org.minidns.record.Record.TYPE;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class QuestionTest {

    private static byte[] createQuestionBytes(int typeValue) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        DnsName.from("example.com").writeToStream(dos);
        dos.writeShort(typeValue);
        dos.writeShort(CLASS.IN.getValue());
        return baos.toByteArray();
    }

    private static Question parseQuestion(byte[] questionBytes) throws IOException {
        return new Question(new DataInputStream(new ByteArrayInputStream(questionBytes)), questionBytes);
    }

    @Test
    public void testQuestion() throws IOException {
        Question question = new Question("example.com", TYPE.MX);
        assertEquals(TYPE.MX.getValue(), question.typeValue);
        assertEquals("example.com.\tIN\tMX", question.toString());
        assertEquals(question, parseQuestion(question.toByteArray()));
    }

    @Test
    public void testQuestionWithUnknownType() throws IOException {
        // 65534 is a private use type, and hence unknown to MiniDNS.
        byte[] questionBytes = createQuestionBytes(65534);
        Question question = parseQuestion(questionBytes);
        assertEquals(TYPE.UNKNOWN, question.type);
        assertEquals(65534, question.typeValue);
        assertEquals("example.com.\tIN\tTYPE65534", question.toString());
        assertArrayEquals(questionBytes, question.toByteArray());
    }

    @Test
    public void testQuestionsWithDifferentUnknownTypesAreNotEqual() throws IOException {
        Question question1 = parseQuestion(createQuestionBytes(65533));
        Question question2 = parseQuestion(createQuestionBytes(65534));
        assertNotEquals(question1, question2);
        assertEquals(question1, parseQuestion(createQuestionBytes(65533)));
    }
}
