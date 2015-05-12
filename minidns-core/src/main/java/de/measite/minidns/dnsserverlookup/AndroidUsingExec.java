package de.measite.minidns.dnsserverlookup;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.net.InetAddress;
import java.util.HashSet;
import java.util.logging.Level;

/**
 * Try to retrieve the list of DNS server by executing getprop.
 */
public class AndroidUsingExec extends AbstractDNSServerLookupMechanism {

    public static final DNSServerLookupMechanism INSTANCE = new AndroidUsingExec();
    public static final int PRIORITY = AndroidUsingReflection.PRIORITY - 1;

    private AndroidUsingExec() {
        super(AndroidUsingExec.class.getSimpleName(), PRIORITY);
    }

    @Override
    public String[] getDnsServerAddresses() {
        try {
            Process process = Runtime.getRuntime().exec("getprop");
            InputStream inputStream = process.getInputStream();
            LineNumberReader lnr = new LineNumberReader(
                new InputStreamReader(inputStream));
            String line = null;
            HashSet<String> server = new HashSet<String>(6);
            while ((line = lnr.readLine()) != null) {
                int split = line.indexOf("]: [");
                if (split == -1) {
                    continue;
                }
                String property = line.substring(1, split);
                String value = line.substring(split + 4, line.length() - 1);
                if (property.endsWith(".dns") || property.endsWith(".dns1") ||
                    property.endsWith(".dns2") || property.endsWith(".dns3") ||
                    property.endsWith(".dns4")) {

                    // normalize the address

                    InetAddress ip = InetAddress.getByName(value);

                    if (ip == null) continue;

                    value = ip.getHostAddress();

                    if (value == null) continue;
                    if (value.length() == 0) continue;

                    server.add(value);
                }
            }
            if (server.size() > 0) {
                return server.toArray(new String[server.size()]);
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Exception in findDNSByExec", e);
        }
        return null;
    }

}
