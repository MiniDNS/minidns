/*
 * Copyright 2015-2022 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.record;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

public class TLSATest {

    @Test
    public void ensureTlsaLutsAreInitialized() {
        TLSA tlsa = new TLSA((byte) 3, (byte) 1, (byte) 2, new byte[] { 0x13, 0x37 });

        assertEquals(3, tlsa.certUsageByte);
        assertNotNull(tlsa.certUsage);

        assertEquals(1, tlsa.selectorByte);
        assertNotNull(tlsa.selector);

        assertEquals(2, tlsa.matchingTypeByte);
        assertNotNull(tlsa.matchingType);
    }
}
