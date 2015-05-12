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

}
