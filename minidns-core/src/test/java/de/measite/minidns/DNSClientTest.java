package de.measite.minidns;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import de.measite.minidns.dnsserverlookup.AndroidUsingExec;
import de.measite.minidns.dnsserverlookup.AndroidUsingReflection;
import de.measite.minidns.dnsserverlookup.DNSServerLookupMechanism;
import de.measite.minidns.dnsserverlookup.HardcodedDNSServerAddresses;

public class DNSClientTest {

    @Test
    public void serverLookupOrderTest() {
        List<DNSServerLookupMechanism> expectedOrder = new ArrayList<>();
        if (isAndroid()) {
            expectedOrder.add(0, AndroidUsingExec.INSTANCE);
            expectedOrder.add(1, AndroidUsingReflection.INSTANCE);
            expectedOrder.add(2, HardcodedDNSServerAddresses.INSTANCE);
        } else {
            expectedOrder.add(0, HardcodedDNSServerAddresses.INSTANCE);
        }
        for (DNSServerLookupMechanism mechanism : DNSClient.LOOKUP_MECHANISMS) {
            if (expectedOrder.isEmpty()) {
                break;
            }
            DNSServerLookupMechanism shouldBeRemovedNext = expectedOrder.get(0);
            if (mechanism == shouldBeRemovedNext) {
                expectedOrder.remove(0);
            } 
        }
        assertTrue(expectedOrder.isEmpty());
    }

    @Test
    public void udpTruncatedTcpFallbackTest() {
        class TestClient extends DNSClient {
            public TestClient() {
                super(new LRUCache(0));
            }

            boolean lastQueryUdp = false;

            @Override
            protected DNSMessage queryUdp(InetAddress address, int port, DNSMessage message) throws IOException {
                assertFalse(lastQueryUdp);
                lastQueryUdp = true;
                DNSMessage msg = new DNSMessage();
                msg.setTruncated(true);
                return msg;
            }

            @Override
            protected DNSMessage queryTcp(InetAddress address, int port, DNSMessage message) throws IOException {
                assertTrue(lastQueryUdp);
                lastQueryUdp = false;
                return null;
            }
        }
        TestClient client = new TestClient();
        assertNull(client.query("example.com", Record.TYPE.A));
        assertFalse(client.lastQueryUdp);
    }

    private static boolean isAndroid() {
        try {
            Class.forName("android.Manifest"); // throws execption when not on Android
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
