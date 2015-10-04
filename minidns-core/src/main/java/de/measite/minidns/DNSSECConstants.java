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

import java.util.HashMap;
import java.util.Map;

public final class DNSSECConstants {
    /**
     * Do not allow to instantiate DNSSECConstants
     */
    private DNSSECConstants() {
    }

    /*
     * DNSSEC Algorithm Numbers
     * http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
     */

    private static Map<Integer, String> signatureAlogorithmLut;

    static {
        signatureAlogorithmLut = new HashMap<>();
        signatureAlogorithmLut.put(1, "RSA/MD5");
        signatureAlogorithmLut.put(2, "Diffie-Hellman");
        signatureAlogorithmLut.put(3, "DSA/SHA1");
        signatureAlogorithmLut.put(5, "RSA/SHA-1");
        signatureAlogorithmLut.put(6, "DSA-NSEC3-SHA1");
        signatureAlogorithmLut.put(7, "RSASHA1-NSEC3-SHA1");
        signatureAlogorithmLut.put(8, "RSA/SHA-256");
        signatureAlogorithmLut.put(10, "RSA/SHA-512");
        signatureAlogorithmLut.put(12, "GOST R 34.10-2001");
        signatureAlogorithmLut.put(13, "ECDSA Curve P-256 with SHA-256");
        signatureAlogorithmLut.put(14, "ECDSA Curve P-384 with SHA-384");
    }

    public static String getSignatureAlgorithmName(int algorithm) {
        if (signatureAlogorithmLut.containsKey(algorithm)) {
            return signatureAlogorithmLut.get(algorithm);
        } else {
            return "Unknown (" + algorithm + ")";
        }
    }

    /**
     * RSA/MD5 (deprecated).
     */
    @Deprecated
    public static final byte SIGNATURE_ALGORITHM_RSAMD5 = 1;

    /**
     * Diffie-Hellman.
     */
    public static final byte SIGNATURE_ALGORITHM_DH = 2;

    /**
     * DSA/SHA1.
     */
    public static final byte SIGNATURE_ALGORITHM_DSA = 3;

    /**
     * RSA/SHA-1.
     */
    public static final byte SIGNATURE_ALGORITHM_RSASHA1 = 5;

    /**
     * DSA-NSEC3-SHA1.
     */
    public static final byte SIGNATURE_ALGORITHM_DSA_NSEC3_SHA1 = 6;

    /**
     * RSASHA1-NSEC3-SHA1.
     */
    public static final byte SIGNATURE_ALGORITHM_RSASHA1_NSEC3_SHA1 = 7;

    /**
     * RSA/SHA-256.
     */
    public static final byte SIGNATURE_ALGORITHM_RSASHA256 = 8;

    /**
     * RSA/SHA-512.
     */
    public static final byte SIGNATURE_ALGORITHM_RSASHA512 = 10;

    /**
     * GOST R 34.10-2001.
     */
    public static final byte SIGNATURE_ALGORITHM_ECC_GOST = 12;

    /**
     * ECDSA Curve P-256 with SHA-256.
     */
    public static final byte SIGNATURE_ALGORITHM_ECDSAP256SHA256 = 13;

    /**
     * ECDSA Curve P-384 with SHA-384.
     */
    public static final byte SIGNATURE_ALGORITHM_ECDSAP384SHA384 = 14;

    /**
     * Reserved for Indirect Keys.
     */
    public static final byte SIGNATURE_ALGORITHM_INDIRECT = (byte) 252;

    /**
     * private algorithm.
     */
    public static final byte SIGNATURE_ALGORITHM_PRIVATEDNS = (byte) 253;

    /**
     * private algorithm OID.
     */
    public static final byte SIGNATURE_ALGORITHM_PRIVATEOID = (byte) 253;

    /*
     * Delegation digest
     * https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
     */

    private static Map<Integer, String> delegationDigestLut;

    static {
        delegationDigestLut = new HashMap<>();
        delegationDigestLut.put(1, "SHA-1");
        delegationDigestLut.put(2, "SHA-256");
        delegationDigestLut.put(3, "GOST R 34.11-94");
        delegationDigestLut.put(4, "SHA-384");
    }

    public static String getDelegationDigestName(int algorithm) {
        if (delegationDigestLut.containsKey(algorithm)) {
            return delegationDigestLut.get(algorithm);
        } else {
            return "Unknown (" + algorithm + ")";
        }
    }

    /**
     * SHA-1.
     */
    public static final byte DIGEST_ALGORITHM_SHA1 = 1;

    /**
     * SHA-256.
     */
    public static final byte DIGEST_ALGORITHM_SHA256 = 2;

    /**
     * GOST R 34.11-94.
     */
    public static final byte DIGEST_ALGORITHM_GOST = 3;

    /**
     * SHA-384.
     */
    public static final byte DIGEST_ALGORITHM_SHA384 = 4;
}
