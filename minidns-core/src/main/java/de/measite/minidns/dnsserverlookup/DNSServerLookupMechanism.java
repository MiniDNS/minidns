package de.measite.minidns.dnsserverlookup;

public interface DNSServerLookupMechanism extends Comparable<DNSServerLookupMechanism> {

    public String getName();

    public int getPriority();

    public String[] getDnsServerAddresses();

}
