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
package org.minidns.integrationtest;

import org.minidns.dane.DaneVerifier;

import javax.net.ssl.HttpsURLConnection;

import org.junit.Ignore;

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;

public class DaneTest {

    @Ignore
    @IntegrationTest
    public static void testOarcDaneGood() throws IOException, CertificateException {
        DaneVerifier daneVerifier = new DaneVerifier();
        daneVerifier.verifiedConnect((HttpsURLConnection) new URL("https://good.dane.dns-oarc.net/").openConnection());
    }

    @Ignore
    @IntegrationTest()
    public static void testOarcDaneBadHash() throws IOException, CertificateException {
        DaneVerifier daneVerifier = new DaneVerifier();
        daneVerifier.verifiedConnect((HttpsURLConnection) new URL("https://bad-hash.dane.dns-oarc.net/").openConnection());
    }

    @Ignore
    @IntegrationTest
    public static void testOarcDaneBadParams() throws IOException, CertificateException {
        DaneVerifier daneVerifier = new DaneVerifier();
        daneVerifier.verifiedConnect((HttpsURLConnection) new URL("https://bad-params.dane.dns-oarc.net/").openConnection());
    }
}
