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

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.edns.EDNSOption;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * OPT payload (see RFC 2671 for details).
 */
public class OPT extends Data {

    public final List<EDNSOption> variablePart;

    public OPT() {
        this(Collections.<EDNSOption>emptyList());
    }

    public OPT(List<EDNSOption> variablePart) {
        this.variablePart = Collections.unmodifiableList(variablePart);
    }

    public static OPT parse(DataInputStream dis, int payloadLength) throws IOException {
        List<EDNSOption> variablePart;
        if (payloadLength == 0) {
            variablePart = Collections.emptyList();
        } else {
            int payloadLeft = payloadLength;
            variablePart = new ArrayList<>(4);
            while (payloadLeft > 0) {
                int optionCode = dis.readUnsignedShort();
                int optionLength = dis.readUnsignedShort();
                byte[] optionData = new byte[optionLength];
                dis.read(optionData);
                EDNSOption ednsOption = EDNSOption.parse(optionCode, optionData);
                variablePart.add(ednsOption);
                payloadLeft -= (2 + 2 + optionLength);
                // Assert that payloadLeft never becomes negative
                assert(payloadLeft >= 0);
            }
        }
        return new OPT(variablePart);
    }

    @Override
    public TYPE getType() {
        return TYPE.OPT;
    }

    @Override
    protected void serialize(DataOutputStream dos) throws IOException {
        for (EDNSOption endsOption : variablePart) {
            endsOption.writeToDos(dos);
        }
    }

}
