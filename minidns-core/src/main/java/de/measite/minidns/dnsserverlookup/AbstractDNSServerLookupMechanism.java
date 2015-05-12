 package de.measite.minidns.dnsserverlookup;

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
    public abstract String[] getDnsServerAddresses();
}
