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
package de.measite.minidns.dnsserverlookup;

/**
 * Return a list of hardcoded DNS servers.
 */
public class HardcodedDNSServerAddresses extends AbstractDNSServerLookupMechanism {

    public static final DNSServerLookupMechanism INSTANCE = new HardcodedDNSServerAddresses();
    public static final int PRIORITY = Integer.MIN_VALUE;

    private HardcodedDNSServerAddresses() {
        super(HardcodedDNSServerAddresses.class.getSimpleName(), PRIORITY);
    }

    @Override
    public String[] getDnsServerAddresses() {
        return new String[]{"8.8.8.8", "[2001:4860:4860::8888]"};
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

}
