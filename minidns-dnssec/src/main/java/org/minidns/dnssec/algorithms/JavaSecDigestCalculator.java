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
package org.minidns.dnssec.algorithms;

import org.minidns.dnssec.DigestCalculator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A {@link DigestCalculator} using {@link MessageDigest}.
 * <p>
 * Instances are shared, e.g. via {@link AlgorithmMap#INSTANCE}, and hence used concurrently. Since {@link MessageDigest}
 * is not thread-safe, access to it is synchronized.
 * </p>
 */
public class JavaSecDigestCalculator implements DigestCalculator {
    private final MessageDigest md;

    public JavaSecDigestCalculator(String algorithm) throws NoSuchAlgorithmException {
        md = MessageDigest.getInstance(algorithm);
    }

    @Override
    public synchronized byte[] digest(byte[] bytes) {
        return md.digest(bytes);
    }
}
