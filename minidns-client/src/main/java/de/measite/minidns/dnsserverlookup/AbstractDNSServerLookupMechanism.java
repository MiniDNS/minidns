/*
 * Copyright 2015-2018 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
 package de.measite.minidns.dnsserverlookup;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

public abstract class AbstractDNSServerLookupMechanism implements DNSServerLookupMechanism {

    protected final static Logger LOGGER = Logger.getLogger(AbstractDNSServerLookupMechanism.class.getName());

    private final String name;
    private final int priority;

    protected AbstractDNSServerLookupMechanism(String name, int priority) {
        this.name = name;
        this.priority = priority;
    }

    @Override
    public final String getName() {
        return name;
    }

    @Override
    public final int getPriority() {
        return priority;
    }

    @Override
    public final int compareTo(DNSServerLookupMechanism other) {
        return getPriority() - other.getPriority();
    }

    @Override
    public abstract List<String> getDnsServerAddresses();

    protected static List<String> toListOfStrings(Collection<? extends InetAddress> inetAddresses) {
        List<String> result = new ArrayList<>(inetAddresses.size());
        for (InetAddress inetAddress : inetAddresses) {
            String address = inetAddress.getHostAddress();
            result.add(address);
        }
        return result;
    }
}
