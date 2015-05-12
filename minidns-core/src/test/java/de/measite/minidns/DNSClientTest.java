package de.measite.minidns;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import de.measite.minidns.dnsserverlookup.AndroidUsingExec;
import de.measite.minidns.dnsserverlookup.AndroidUsingReflection;
import de.measite.minidns.dnsserverlookup.DNSServerLookupMechanism;
import de.measite.minidns.dnsserverlookup.HardcodedDNSServerAddresses;

public class DNSClientTest {

    @Test
    public void oracleOrderTest() {
        List<DNSServerLookupMechanism> expectedOrder = new ArrayList<>();
        expectedOrder.add(0, AndroidUsingExec.INSTANCE);
        expectedOrder.add(1, AndroidUsingReflection.INSTANCE);
        expectedOrder.add(2, HardcodedDNSServerAddresses.INSTANCE);
        for (DNSServerLookupMechanism mechanism : DNSClient.LOOKUP_MECHANISMS) {
            if (expectedOrder.isEmpty()) {
                break;
            }
            DNSServerLookupMechanism shouldBeRemovedNext = expectedOrder.get(0);
            if (mechanism == shouldBeRemovedNext) {
                expectedOrder.remove(0);
            } 
        }
        assert(expectedOrder.isEmpty());
    }
}
