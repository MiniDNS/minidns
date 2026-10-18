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

import org.minidns.dnsname.DnsName;
import org.minidns.dnssec.DnssecClient;
import org.minidns.dnssec.DnssecQueryResult;
import org.minidns.dnssec.DnssecUnverifiedReason;
import org.minidns.record.CNAME;
import org.minidns.record.Data;
import org.minidns.record.Record;
import org.minidns.record.TLSA;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * A helper class to validate the usage of TLSA records.
 */
public class DaneVerifier {
    private static final Logger LOGGER = Logger.getLogger(DaneVerifier.class.getName());

    /**
     * The maximum number of CNAMEs followed when looking up the TLSA RRs. This also prevents looping on CNAME loops.
     */
    private static final int MAX_CNAME_CHAIN_LENGTH = 16;

    private final DnssecClient client;

    public DaneVerifier() {
        this(new DnssecClient());
    }

    public DaneVerifier(DnssecClient client) {
        this.client = client;
    }

    /**
     * Verifies the certificate chain in an active {@link SSLSocket}. The socket must be connected.
     *
     * @param socket A connected {@link SSLSocket} whose certificate chain shall be verified using DANE.
     * @return Whether the DANE verification is the only requirement according to the TLSA record.
     * If this method returns {@code false}, additional PKIX validation is required.
     * @throws CertificateException if the certificate chain provided differs from the one enforced using DANE.
     * @see #daneVerify(SSLSocket)
     */
    public boolean verify(SSLSocket socket) throws CertificateException {
        return daneVerify(socket).isFullyVerified();
    }

    /**
     * Verifies the certificate chain in an active {@link SSLSocket}. The socket must be connected.
     *
     * @param socket A connected {@link SSLSocket} whose certificate chain shall be verified using DANE.
     * @return The result of the DANE verification.
     * @throws CertificateException if the certificate chain provided differs from the one enforced using DANE.
     */
    public DaneVerificationResult daneVerify(SSLSocket socket) throws CertificateException {
        if (!socket.isConnected()) {
            throw new IllegalStateException("Socket not yet connected.");
        }
        return daneVerify(socket.getSession());
    }

    /**
     * Verifies the certificate chain in an active {@link SSLSession}.
     *
     * @param session An active {@link SSLSession} whose certificate chain shall be verified using DANE.
     * @return Whether the DANE verification is the only requirement according to the TLSA record.
     * If this method returns {@code false}, additional PKIX validation is required.
     * @throws CertificateException if the certificate chain provided differs from the one enforced using DANE.
     * @see #daneVerify(SSLSession)
     */
    public boolean verify(SSLSession session) throws CertificateException {
        return daneVerify(session).isFullyVerified();
    }

    /**
     * Verifies the certificate chain in an active {@link SSLSession}.
     *
     * @param session An active {@link SSLSession} whose certificate chain shall be verified using DANE.
     * @return The result of the DANE verification.
     * @throws CertificateException if the certificate chain provided differs from the one enforced using DANE.
     */
    public DaneVerificationResult daneVerify(SSLSession session) throws CertificateException {
        try {
            return daneVerify(convert(session.getPeerCertificates()), session.getPeerHost(), session.getPeerPort());
        } catch (SSLPeerUnverifiedException e) {
            throw new CertificateException("Peer not verified", e);
        }
    }

    /**
     * Verifies a certificate chain to be valid when used with the given connection details using DANE.
     *
     * @param chain A certificate chain that should be verified using DANE.
     * @param hostName The DNS name of the host this certificate chain belongs to.
     * @param port The port number that was used to reach the server providing the certificate chain in question.
     * @return Whether the DANE verification is the only requirement according to the TLSA record.
     * If this method returns {@code false}, additional PKIX validation is required.
     * @throws CertificateException if the certificate chain provided differs from the one enforced using DANE.
     * @see #daneVerify(X509Certificate[], String, int)
     */
    public boolean verifyCertificateChain(X509Certificate[] chain, String hostName, int port) throws CertificateException {
        return daneVerify(chain, hostName, port).isFullyVerified();
    }

    /**
     * Verifies a certificate chain to be valid when used with the given connection details using DANE.
     * <p>
     * Unlike {@link #verifyCertificateChain(X509Certificate[], String, int)}, this method allows the caller to
     * distinguish between DANE not being applicable and a TLSA record matching the certificate while still requiring
     * PKIX validation, as it is the case for the certificate usage PKIX-EE (1).
     * </p>
     *
     * @param chain A certificate chain that should be verified using DANE.
     * @param hostName The DNS name of the host this certificate chain belongs to.
     * @param port The port number that was used to reach the server providing the certificate chain in question.
     * @return The result of the DANE verification.
     * @throws CertificateException if the certificate chain provided differs from the one enforced using DANE.
     */
    public DaneVerificationResult daneVerify(X509Certificate[] chain, String hostName, int port) throws CertificateException {
        DnsName req = DnsName.from("_" + port + "._tcp." + hostName);
        DnsName tlsaName = req;
        List<Record<? extends Data>> answers;
        int remainingCnames = MAX_CNAME_CHAIN_LENGTH;
        while (true) {
            DnssecQueryResult result;
            try {
                result = client.queryDnssec(tlsaName, Record.TYPE.TLSA);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            // TODO: We previously used the AD bit here. This allowed non-DNSSEC aware clients to be plugged into
            // DaneVerifier, which, in turn, allows to use a trusted forward as DNSSEC validator. Is this a good idea?
            if (!result.isAuthenticData()) {
                String msg = "Got TLSA response from DNS server, but was not signed properly.";
                msg += " Reasons:";
                for (DnssecUnverifiedReason reason : result.getUnverifiedReasons()) {
                     msg += " " + reason;
                }
                LOGGER.info(msg);
                return DaneVerificationResult.notAuthenticated;
            }
            answers = result.dnsQueryResult.response.answerSection;

            // The TLSA RRs may be provisioned via CNAMEs (RFC 6698 § A.2.1). Since the response is authentic, all
            // CNAME RRs in the answer section have been validated, so we can de-alias the queried name.
            DnsName queriedName = tlsaName;
            while (true) {
                DnsName target = findCnameTarget(tlsaName, answers);
                if (target == null) break;
                if (remainingCnames-- == 0) {
                    LOGGER.warning("CNAME chain for " + req + " exceeds " + MAX_CNAME_CHAIN_LENGTH + " CNAMEs, not using TLSA RRs");
                    return DaneVerificationResult.noUsableTlsaRecords;
                }
                tlsaName = target;
            }

            // If the response did not include the RRs of the CNAME target, e.g., because the target is in another
            // zone, then query the target.
            if (tlsaName.equals(queriedName) || containsTlsa(tlsaName, answers)) {
                break;
            }
        }

        List<DaneCertificateException.CertificateMismatch> certificateMismatchExceptions = new ArrayList<>();
        DaneVerificationResult verificationResult = DaneVerificationResult.noUsableTlsaRecords;
        for (Record<? extends Data> record : answers) {
            if (record.type == Record.TYPE.TLSA && record.name.equals(tlsaName)) {
                TLSA tlsa = (TLSA) record.payloadData;
                DaneVerificationResult recordResult;
                try {
                    recordResult = checkCertificateMatches(chain[0], tlsa, hostName);
                } catch (DaneCertificateException.CertificateMismatch certificateMismatchException) {
                    // Record the mismatch and only throw an exception if no
                    // TLSA RR is able to verify the cert. This allows for TLSA
                    // certificate rollover.
                    certificateMismatchExceptions.add(certificateMismatchException);
                    continue;
                }

                if (recordResult == DaneVerificationResult.verified) {
                    return recordResult;
                }
                if (recordResult == DaneVerificationResult.matchedPkixRequired) {
                    // Keep looking, as another TLSA RR may make PKIX validation unnecessary.
                    verificationResult = recordResult;
                }
            }
        }

        if (!verificationResult.isDaneMatch() && !certificateMismatchExceptions.isEmpty()) {
            throw new DaneCertificateException.MultipleCertificateMismatchExceptions(certificateMismatchExceptions);
        }

        return verificationResult;
    }

    private static DnsName findCnameTarget(DnsName name, List<Record<? extends Data>> records) {
        for (Record<? extends Data> record : records) {
            if (record.type == Record.TYPE.CNAME && record.name.equals(name)) {
                return ((CNAME) record.payloadData).target;
            }
        }
        return null;
    }

    private static boolean containsTlsa(DnsName name, List<Record<? extends Data>> records) {
        for (Record<? extends Data> record : records) {
            if (record.type == Record.TYPE.TLSA && record.name.equals(name)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if the given certificate matches the given TLSA record.
     *
     * @param cert The certificate to check.
     * @param tlsa The TLSA record to check the certificate against.
     * @param hostName The DNS name of the host the certificate belongs to, used for logging.
     * @return {@link DaneVerificationResult#verified} or {@link DaneVerificationResult#matchedPkixRequired} if the
     * certificate matches, or {@link DaneVerificationResult#noUsableTlsaRecords} if the TLSA record is not usable.
     * @throws DaneCertificateException.CertificateMismatch if the TLSA record is usable but does not match.
     */
    private static DaneVerificationResult checkCertificateMatches(X509Certificate cert, TLSA tlsa, String hostName) throws CertificateException {
        if (tlsa.certUsage == null) {
            LOGGER.warning("TLSA certificate usage byte " + tlsa.certUsageByte + " is not supported while verifying " + hostName);
            return DaneVerificationResult.noUsableTlsaRecords;
        }

        switch (tlsa.certUsage) {
        case serviceCertificateConstraint: // PKIX-EE
        case domainIssuedCertificate: // DANE-EE
            break;
        case caConstraint: // PKIX-TA
        case trustAnchorAssertion: // DANE-TA
        default:
            LOGGER.warning("TLSA certificate usage " + tlsa.certUsage + " (" + tlsa.certUsageByte + ") not supported while verifying " + hostName);
            return DaneVerificationResult.noUsableTlsaRecords;
        }

        if (tlsa.selector == null) {
            LOGGER.warning("TLSA selector byte " + tlsa.selectorByte + " is not supported while verifying " + hostName);
            return DaneVerificationResult.noUsableTlsaRecords;
        }

        byte[] comp = null;
        switch (tlsa.selector) {
            case fullCertificate:
                comp = cert.getEncoded();
                break;
            case subjectPublicKeyInfo:
                comp = cert.getPublicKey().getEncoded();
                break;
            default:
                LOGGER.warning("TLSA selector " + tlsa.selector + " (" + tlsa.selectorByte + ") not supported while verifying " + hostName);
                return DaneVerificationResult.noUsableTlsaRecords;
        }

        if (tlsa.matchingType == null) {
            LOGGER.warning("TLSA matching type byte " + tlsa.matchingTypeByte + " is not supported while verifying " + hostName);
            return DaneVerificationResult.noUsableTlsaRecords;
        }

        switch (tlsa.matchingType) {
            case noHash:
                break;
            case sha256:
                try {
                    comp = MessageDigest.getInstance("SHA-256").digest(comp);
                } catch (NoSuchAlgorithmException e) {
                    throw new CertificateException("Verification using TLSA failed: could not SHA-256 for matching", e);
                }
                break;
            case sha512:
                try {
                    comp = MessageDigest.getInstance("SHA-512").digest(comp);
                } catch (NoSuchAlgorithmException e) {
                    throw new CertificateException("Verification using TLSA failed: could not SHA-512 for matching", e);
                }
                break;
            default:
                LOGGER.warning("TLSA matching type " + tlsa.matchingType + " not supported while verifying " + hostName);
                return DaneVerificationResult.noUsableTlsaRecords;
        }

        boolean matches = tlsa.certificateAssociationEquals(comp);
        if (!matches) {
            throw new DaneCertificateException.CertificateMismatch(tlsa, comp);
        }

        // domain issued certificate does not require further verification,
        // service certificate constraint does.
        if (tlsa.certUsage == TLSA.CertUsage.domainIssuedCertificate) {
            return DaneVerificationResult.verified;
        }
        return DaneVerificationResult.matchedPkixRequired;
    }

    /**
     * Invokes {@link HttpsURLConnection#connect()} in a DANE verified fashion.
     * This method must be called before {@link HttpsURLConnection#connect()} is invoked.
     *
     * If a SSLSocketFactory was set on this HttpsURLConnection, it will be ignored. You can use
     * {@link #verifiedConnect(HttpsURLConnection, X509TrustManager)} to inject a custom {@link TrustManager}.
     *
     * @param conn connection to be connected.
     * @return The {@link HttpsURLConnection} after being connected.
     * @throws IOException when the connection could not be established.
     * @throws CertificateException if there was an exception while verifying the certificate.
     */
    public HttpsURLConnection verifiedConnect(HttpsURLConnection conn) throws IOException, CertificateException {
        return verifiedConnect(conn, null);
    }

    /**
     * Invokes {@link HttpsURLConnection#connect()} in a DANE verified fashion.
     * This method must be called before {@link HttpsURLConnection#connect()} is invoked.
     *
     * If a SSLSocketFactory was set on this HttpsURLConnection, it will be ignored.
     *
     * @param conn         connection to be connected.
     * @param trustManager A non-default {@link TrustManager} to be used.
     * @return The {@link HttpsURLConnection} after being connected.
     * @throws IOException when the connection could not be established.
     * @throws CertificateException if there was an exception while verifying the certificate.
     */
    public HttpsURLConnection verifiedConnect(HttpsURLConnection conn, X509TrustManager trustManager) throws IOException, CertificateException {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            ExpectingTrustManager expectingTrustManager = new ExpectingTrustManager(trustManager);
            context.init(null, new TrustManager[] {expectingTrustManager}, null);
            conn.setSSLSocketFactory(context.getSocketFactory());
            conn.connect();
            boolean fullyVerified = verifyCertificateChain(convert(conn.getServerCertificates()), conn.getURL().getHost(),
                    conn.getURL().getPort() < 0 ? conn.getURL().getDefaultPort() : conn.getURL().getPort());
            // If fullyVerified is true then it's the DANE verification performed by verifiyCertificateChain() is
            // sufficient to verify the certificate and we ignore possible pending exceptions of ExpectingTrustManager.
            if (!fullyVerified && expectingTrustManager.hasException()) {
                throw new IOException("Peer verification failed using PKIX", expectingTrustManager.getException());
            }
            return conn;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate[] convert(Certificate[] certificates) {
        List<X509Certificate> certs = new ArrayList<>();
        for (Certificate certificate : certificates) {
            if (certificate instanceof X509Certificate) {
                certs.add((X509Certificate) certificate);
            }
        }
        return certs.toArray(new X509Certificate[certs.size()]);
    }
}
