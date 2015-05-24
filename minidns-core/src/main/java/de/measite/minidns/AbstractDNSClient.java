package de.measite.minidns;

import java.io.IOException;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Random;
import java.util.logging.Logger;

import de.measite.minidns.Record.CLASS;
import de.measite.minidns.Record.TYPE;

/**
 * A minimal DNS client for SRV/A/AAAA/NS and CNAME lookups, with IDN support.
 * This circumvents the missing javax.naming package on android.
 */
public abstract class AbstractDNSClient {

    protected static final Logger LOGGER = Logger.getLogger(AbstractDNSClient.class.getName());

    /**
     * The internal random class for sequence generation.
     */
    protected final Random random;

    /**
     * The buffer size for dns replies.
     */
    protected int bufferSize = 1500;

    /**
     * DNS timeout.
     */
    protected int timeout = 5000;

    /**
     * The internal DNS cache.
     */
    protected DNSCache cache;

    /**
     * Create a new DNS client with the given DNS cache.
     * @param cache The backend DNS cache.
     */
    protected AbstractDNSClient(DNSCache cache) {
        this();
        this.cache = cache;
    }

    /**
     * Creates a new client that uses the given Map as cache.
     * @param cache the Map to use as cache for DNS results.
     */
    protected AbstractDNSClient(final Map<Question, DNSMessage> cache) {
        this();
        if (cache != null)
            this.cache = new DNSCache() {
                public void put(Question q, DNSMessage message) { cache.put(q, message); }
                public DNSMessage get(Question q) { return cache.get(q); }
            };
    }

    /**
     * Create a new DNS client without any caching.
     */
    protected AbstractDNSClient() {
        Random random;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e1) {
            random = new SecureRandom();
        }
        this.random = random;
    }

    /**
     * Retrieve the current dns query timeout, in milliseconds.
     * @return the current dns query timeout in milliseconds.
     */
    public int getTimeout() {
        return timeout;
    }

    /**
     * Change the dns query timeout for all future queries. The timeout
     * must be specified in milliseconds.
     * @param timeout new dns query timeout in milliseconds.
     */
    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    /**
     * Query the system nameservers for a single entry of any class.
     *
     * This can be used to determine the name server version, if name
     * is version.bind, type is TYPE.TXT and clazz is CLASS.CH.
     *
     * @param name The DNS name to request.
     * @param type The DNS type to request (SRV, A, AAAA, ...).
     * @param clazz The class of the request (usually IN for Internet).
     * @return The response (or null on timeout/error).
     */
    public final DNSMessage query(String name, TYPE type, CLASS clazz)
    {
        Question q = new Question(name, type, clazz);
        return query(q);
    }

    /**
     * Query the system nameservers for a single entry of the class IN
     * (which is used for MX, SRV, A, AAAA and most other RRs).
     *
     * @param name The DNS name to request.
     * @param type The DNS type to request (SRV, A, AAAA, ...).
     * @return The response (or null on timeout/error).
     */
    public final DNSMessage query(String name, TYPE type)
    {
        Question q = new Question(name, type, CLASS.IN);
        return query(q);
    }


    /**
     * Query the system DNS server for one entry.
     * @param q The question section of the DNS query.
     * @return The response (or null on timeout/error).
     */
    public abstract DNSMessage query(Question q);
    

    /**
     * Query a specific server for one entry.
     * @param q The question section of the DNS query.
     * @param address The dns server address.
     * @param port the dns port.
     * @return The response (or null on timeout/error).
     * @throws IOException On IOErrors.
     */
    public abstract DNSMessage query(Question q, InetAddress address, int port) throws IOException;

    /**
     * Query a nameserver for a single entry.
     * @param name The DNS name to request.
     * @param type The DNS type to request (SRV, A, AAAA, ...).
     * @param clazz The class of the request (usually IN for Internet).
     * @param address The DNS server address.
     * @param port The DNS server port.
     * @return The response (or null on timeout / failure).
     * @throws IOException On IO Errors.
     */
    public DNSMessage query(String name, TYPE type, CLASS clazz, InetAddress address, int port)
        throws IOException
    {
        Question q = new Question(name, type, clazz);
        return query(q, address, port);
    }

    /**
     * Query a nameserver for a single entry.
     * @param name The DNS name to request.
     * @param type The DNS type to request (SRV, A, AAAA, ...).
     * @param clazz The class of the request (usually IN for Internet).
     * @param address The DNS server host.
     * @return The response (or null on timeout / failure).
     * @throws IOException On IO Errors.
     */
    public DNSMessage query(String name, TYPE type, CLASS clazz, InetAddress address)
        throws IOException
    {
        Question q = new Question(name, type, clazz);
        return query(q, address);
    }

    /**
     * Query a specific server for one entry.
     * @param q The question section of the DNS query.
     * @param host The dns server host.
     * @return The response (or null on timeout/error).
     * @throws IOException On IOErrors.
     */
    public DNSMessage query(Question q, String host) throws IOException {
        return query(q, InetAddress.getByName(host), 53);
    }

    /**
     * Query a specific server for one entry.
     * @param q The question section of the DNS query.
     * @param address The dns server address.
     * @return The response (or null on timeout/error).
     * @throws IOException On IOErrors.
     */
    public DNSMessage query(Question q, InetAddress address) throws IOException {
        return query(q, address, 53);
    }
}
