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
package de.measite.minidns.dane.java7;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.dane.DaneVerifier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

public class DaneExtendedTrustManager extends X509ExtendedTrustManager {
    private final static Logger LOGGER = Logger.getLogger(DaneExtendedTrustManager.class.getName());

    private final X509TrustManager base;
    private final DaneVerifier verifier;

    public static void inject() {
        inject(new DaneExtendedTrustManager());
    }

    public static void inject(DaneExtendedTrustManager trustManager) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, null);
            SSLContext.setDefault(sslContext);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    public DaneExtendedTrustManager() {
        this(getDefaultTrustManager());
    }

    public DaneExtendedTrustManager(AbstractDNSClient client) {
        this(client, getDefaultTrustManager());
    }

    private static X509TrustManager getDefaultTrustManager() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            for (TrustManager trustManager : tmf.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager)
                    return (X509TrustManager) trustManager;
            }
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException("X.509 not supported.", e);
        }
        return null;
    }

    public DaneExtendedTrustManager(X509TrustManager base) {
        this(new DaneVerifier(), base);
    }

    public DaneExtendedTrustManager(AbstractDNSClient client, X509TrustManager base) {
        this(new DaneVerifier(client), base);
    }

    public DaneExtendedTrustManager(DaneVerifier verifier, X509TrustManager base) {
        this.verifier = verifier;
        this.base = base;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (base == null) {
            LOGGER.warning("DaneExtendedTrustManager invalidly used for client certificate check and no fallback X509TrustManager specified");
        } else {
            LOGGER.info("DaneExtendedTrustManager invalidly used for client certificate check forwarding request to fallback X509TrustManage");
            if (base instanceof X509ExtendedTrustManager) {
                ((X509ExtendedTrustManager) base).checkClientTrusted(chain, authType, socket);
            } else {
                base.checkClientTrusted(chain, authType);
            }
        }
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (!verifier.verifyCertificateChain(chain, socket.getInetAddress().getHostName(), socket.getPort())) {
            if (base instanceof X509ExtendedTrustManager) {
                ((X509ExtendedTrustManager) base).checkServerTrusted(chain, authType, socket);
            } else {
                base.checkClientTrusted(chain, authType);
            }
        }
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        if (base == null) {
            LOGGER.warning("DaneExtendedTrustManager invalidly used for client certificate check and no fallback X509TrustManager specified");
        } else {
            LOGGER.info("DaneExtendedTrustManager invalidly used for client certificate check, forwarding request to fallback X509TrustManage");
            if (base instanceof X509ExtendedTrustManager) {
                ((X509ExtendedTrustManager) base).checkClientTrusted(chain, authType, engine);
            } else {
                base.checkClientTrusted(chain, authType);
            }
        }
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        if (!verifier.verifyCertificateChain(chain, engine.getPeerHost(), engine.getPeerPort())) {
            if (base instanceof X509ExtendedTrustManager) {
                ((X509ExtendedTrustManager) base).checkServerTrusted(chain, authType, engine);
            } else {
                base.checkClientTrusted(chain, authType);
            }
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (base == null) {
            LOGGER.warning("DaneExtendedTrustManager invalidly used for client certificate check and no fallback X509TrustManager specified");
        } else {
            LOGGER.info("DaneExtendedTrustManager invalidly used for client certificate check, forwarding request to fallback X509TrustManage");
            base.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        LOGGER.info("DaneExtendedTrustManager cannot be used without hostname information, forwarding request to fallback X509TrustManage");
        base.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return base.getAcceptedIssuers();
    }
}
