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
package de.measite.minidns;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MiniDNSInitialization {

    private static final Logger LOGGER = Logger.getLogger(MiniDNSInitialization.class.getName());

    static final String VERSION;

    static {
        String miniDnsVersion;
        BufferedReader reader = null;
        try {
            InputStream is = MiniDNSInitialization.class.getClassLoader().getResourceAsStream("de.measite.minidns/version");
            reader = new BufferedReader(new InputStreamReader(is));
            miniDnsVersion = reader.readLine();
        } catch(Exception e) {
            LOGGER.log(Level.SEVERE, "Could not determine MiniDNS version", e);
            miniDnsVersion = "unkown";
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "IOException closing stream", e);
                }
            }
        }
        VERSION = miniDnsVersion;
    }
}
