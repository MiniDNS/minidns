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
 package org.minidns.dnsserverlookup;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

public abstract class AbstractDnsServerLookupMechanism implements DnsServerLookupMechanism {

    protected final static Logger LOGGER = Logger.getLogger(AbstractDnsServerLookupMechanism.class.getName());

    private final String name;
    private final int priority;

    protected AbstractDnsServerLookupMechanism(String name, int priority) {
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
    public final int compareTo(DnsServerLookupMechanism other) {
        return getPriority() - other.getPriority();
    }

    @Override
    public abstract List<IPPortPair> getDnsServerAddresses();

    protected static List<String> toListOfStrings(Collection<? extends InetAddress> inetAddresses) {
        List<String> result = new ArrayList<>(inetAddresses.size());
        for (InetAddress inetAddress : inetAddresses) {
            String address = inetAddress.getHostAddress();
            result.add(address);
        }
        return result;
    }

    protected static List<IPPortPair> inetAddressCollectionToListOfIPPortPairs(Collection<? extends InetAddress> inetAddresses){
        List<IPPortPair> result = new ArrayList<>(inetAddresses.size());
        for (InetAddress inetAddress : inetAddresses) {
            String address = inetAddress.getHostAddress();
            result.add(new IPPortPair(address, IPPortPair.DEFAULT_PORT));
        }
        return result;
    }

    protected static List<IPPortPair> stringCollectionToListOfIPPortPairs(Collection<String> serverAddresses){
        List<IPPortPair> result = new ArrayList<>(serverAddresses.size());
        for (String address : serverAddresses) {
            result.add(new IPPortPair(address, IPPortPair.DEFAULT_PORT));
        }
        return result;
    }
}
