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
package org.minidns.dane;

/**
 * The result of a DANE verification performed by {@link DaneVerifier}.
 * <p>
 * Note that a TLSA record set which contains usable records, none of which matches the certificate, does not result
 * in a {@link DaneVerificationResult}, but in a {@link DaneCertificateException} being thrown.
 * </p>
 */
public enum DaneVerificationResult {

    /**
     * The TLSA response was not DNSSEC authenticated. DANE does not apply and PKIX validation is required.
     */
    notAuthenticated,

    /**
     * The TLSA response was DNSSEC authenticated, but contained no usable TLSA records, that is, it either contained
     * no TLSA records at all or only TLSA records with unsupported parameters. DANE does not apply and PKIX validation
     * is required.
     */
    noUsableTlsaRecords,

    /**
     * A TLSA record with the certificate usage PKIX-EE (1) matched the certificate. The DANE verification was
     * successful, but PKIX validation is still required.
     */
    matchedPkixRequired,

    /**
     * A TLSA record with the certificate usage DANE-EE (3) matched the certificate. The certificate is verified and no
     * further validation is required.
     */
    verified,
    ;

    /**
     * Check if the DANE verification alone is sufficient to verify the certificate.
     *
     * @return {@code true} if no further PKIX validation is required.
     */
    public boolean isFullyVerified() {
        return this == verified;
    }

    /**
     * Check if a TLSA record matched the certificate.
     *
     * @return {@code true} if a TLSA record matched the certificate.
     */
    public boolean isDaneMatch() {
        return this == matchedPkixRequired || this == verified;
    }
}
