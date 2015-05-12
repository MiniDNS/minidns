package de.measite.minidns.dnsserverlookup;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.logging.Level;

/**
 * Try to retrieve the list of DNS server by calling SystemProperties.
 */
public class AndroidUsingReflection extends AbstractDNSServerLookupMechanism {

    public static final DNSServerLookupMechanism INSTANCE = new AndroidUsingReflection();
    public static final int PRIORITY = 1000;

    protected AndroidUsingReflection() {
        super(AndroidUsingReflection.class.getSimpleName(), PRIORITY);
    }

    @Override
    public String[] getDnsServerAddresses() {
        try {
            Class<?> SystemProperties =
                    Class.forName("android.os.SystemProperties");
            Method method = SystemProperties.getMethod("get",
                    new Class<?>[] { String.class });

            ArrayList<String> servers = new ArrayList<String>(5);

            for (String propKey : new String[] {
                    "net.dns1", "net.dns2", "net.dns3", "net.dns4"}) {

                String value = (String)method.invoke(null, propKey);

                if (value == null) continue;
                if (value.length() == 0) continue;
                if (servers.contains(value)) continue;

                InetAddress ip = InetAddress.getByName(value);

                if (ip == null) continue;

                value = ip.getHostAddress();

                if (value == null) continue;
                if (value.length() == 0) continue;
                if (servers.contains(value)) continue;

                servers.add(value);
            }

            if (servers.size() > 0) {
                return servers.toArray(new String[servers.size()]);
            }
        } catch (Exception e) {
            // we might trigger some problems this way
            LOGGER.log(Level.WARNING, "Exception in findDNSByReflection", e);
        }
        return null;
    }

}
