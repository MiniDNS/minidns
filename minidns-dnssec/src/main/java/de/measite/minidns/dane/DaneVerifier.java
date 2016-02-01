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
package de.measite.minidns.dane;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.LRUCache;
import de.measite.minidns.Record;
import de.measite.minidns.dnssec.DNSSECClient;
import de.measite.minidns.dnssec.DNSSECMessage;
import de.measite.minidns.dnssec.UnverifiedReason;
import de.measite.minidns.record.TLSA;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.cert.CertificateEncodingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A helper class to validate the usage of TLSA records.
 */
public class DaneVerifier {
    private final static Logger LOGGER = Logger.getLogger(DaneVerifier.class.getName());

    private final AbstractDNSClient client;

    public DaneVerifier() {
        this(new DNSSECClient(new LRUCache(1024)));
    }

    public DaneVerifier(AbstractDNSClient client) {
        this.client = client;
    }

    /**
     * Verifies the certificate chain in an active {@link SSLSocket}. The socket must be connected.
     *
     * @param socket A connected {@link SSLSocket} whose certificate chain shall be verified using DANE.
     * @return Whether the DANE verification is the only requirement according to the TLSA record.
     * If this method returns {@code false}, additional PKIX validation is required.
     * @throws CertificateException if the certificate chain provided differs from the one enforced using DANE.
     */
    public boolean verify(SSLSocket socket) throws CertificateException {
        if (!socket.isConnected()) {
            throw new IllegalStateException("Socket not yet connected.");
        }
        return verify(socket.getSession());
    }

    /**
     * Verifies the certificate chain in an active {@link SSLSession}.
     *
     * @param session An active {@link SSLSession} whose certificate chain shall be verified using DANE.
     * @return Whether the DANE verification is the only requirement according to the TLSA record.
     * If this method returns {@code false}, additional PKIX validation is required.
     * @throws CertificateException if the certificate chain provided differs from the one enforced using DANE.
     */
    public boolean verify(SSLSession session) throws CertificateException {
        try {
            return verifyCertificateChain(convert(session.getPeerCertificateChain()), session.getPeerHost(), session.getPeerPort());
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
     */
    public boolean verifyCertificateChain(X509Certificate[] chain, String hostName, int port) throws CertificateException {
        String req = "_" + port + "._tcp." + hostName;
        DNSMessage res = client.query(req, Record.TYPE.TLSA);
        if (!res.isAuthenticData()) {
            String msg = "Got TLSA response from DNS server, but was not signed properly.";
            if (res instanceof DNSSECMessage) {
                msg += " Reasons:";
                for (UnverifiedReason reason : ((DNSSECMessage) res).getUnverifiedReasons()) {
                    msg += " " + reason;
                }
            }
            LOGGER.info(msg);
            return false;
        }
        TLSA tlsa = null;
        for (Record record : res.getAnswers()) {
            if (record.type == Record.TYPE.TLSA && record.name.equals(req)) {
                tlsa = (TLSA) record.payloadData;
                break;
            }
        }
        if (tlsa != null) {
            switch (tlsa.certUsage) {
                case TLSA.CERT_USAGE_SERVICE_CERTIFICATE_CONSTRAINT:
                case TLSA.CERT_USAGE_DOMAIN_ISSUED_CERTIFICATE:
                    if (!checkCertificateMatches(chain[0], tlsa)) {
                        throw new CertificateException("Verification using TLSA failed: certificate differs");
                    }
                    // domain issued certificate does not require further verification, 
                    // service certificate constraint does.
                    return tlsa.certUsage == TLSA.CERT_USAGE_DOMAIN_ISSUED_CERTIFICATE;
                case TLSA.CERT_USAGE_CA_CONSTRAINT:
                case TLSA.CRET_USAGE_TRUST_ANCHOR_ASSERTION:
                default:
                    LOGGER.info("TLSA certificate usage " + tlsa.certUsage + " not supported for " + hostName);
                    return false;
            }
        }
        return false;
    }

    private static boolean checkCertificateMatches(X509Certificate cert, TLSA tlsa) throws CertificateException {
        byte[] comp = null;
        switch (tlsa.selector) {
            case TLSA.SELECTOR_FULL_CERTIFICATE:
                comp = cert.getEncoded();
                break;
            case TLSA.SELECTOR_SUBJECT_PUBLIC_KEY_INFO:
                comp = cert.getPublicKey().getEncoded();
                break;
        }
        if (comp == null) {
            throw new CertificateException("Verification using TLSA failed: could not create matching bytes");
        }
        switch (tlsa.matchingType) {
            case TLSA.MATCHING_TYPE_NO_HASH:
                break;
            case TLSA.MATCHING_TYPE_SHA_256:
                try {
                    comp = MessageDigest.getInstance("SHA-256").digest(comp);
                } catch (NoSuchAlgorithmException e) {
                    throw new CertificateException("Verification using TLSA failed: could not SHA-256 for matching", e);
                }
                break;
            case TLSA.MATCHING_TYPE_SHA_512:
                try {
                    comp = MessageDigest.getInstance("SHA-512").digest(comp);
                } catch (NoSuchAlgorithmException e) {
                    throw new CertificateException("Verification using TLSA failed: could not SHA-512 for matching", e);
                }
                break;
        }
        return Arrays.equals(comp, tlsa.certificateAssociation);
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
     */
    public HttpsURLConnection verifiedConnect(HttpsURLConnection conn) throws IOException {
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
     */
    public HttpsURLConnection verifiedConnect(HttpsURLConnection conn, X509TrustManager trustManager) throws IOException {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            ExpectingTrustManager expectingTrustManager = new ExpectingTrustManager(trustManager);
            context.init(null, new TrustManager[]{expectingTrustManager}, null);
            conn.setSSLSocketFactory(context.getSocketFactory());
            conn.connect();
            boolean fullyVerified = verifyCertificateChain(convert(conn.getServerCertificates()), conn.getURL().getHost(),
                    conn.getURL().getPort() < 0 ? conn.getURL().getDefaultPort() : conn.getURL().getPort());
            if (!fullyVerified && expectingTrustManager.hasException()) {
                throw new IOException("Peer verification failed using PKIX", expectingTrustManager.getException());
            }
            return conn;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new IOException("Peer verification failed using DANE", e);
        }
    }

    private X509Certificate[] convert(Certificate[] certificates) {
        List<X509Certificate> certs = new ArrayList<>();
        for (Certificate certificate : certificates) {
            if (certificate instanceof X509Certificate) {
                certs.add((X509Certificate) certificate);
            }
        }
        return certs.toArray(new X509Certificate[certs.size()]);
    }

    private X509Certificate[] convert(javax.security.cert.X509Certificate[] certificates) {
        X509Certificate[] certs = new X509Certificate[certificates.length];
        for (int i = 0; i < certificates.length; i++) {
            try {
                certs[i] = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificates[i].getEncoded()));
            } catch (CertificateException | CertificateEncodingException e) {
                LOGGER.log(Level.WARNING, "Could not convert", e);
            }
        }
        return certs;
    }
}
