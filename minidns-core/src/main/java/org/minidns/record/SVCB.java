package org.minidns.record;

import org.minidns.constants.SVCBConstants;
import org.minidns.dnsname.DnsName;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * SVCB Record Type (Service binding)
 *
 * @see <a href="https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01">draft-ietf-dnsop-svcb-https-01: Service binding and parameter specification via the DNS (DNS SVCB and HTTPS RRs)</a>
 */
class SVCB extends RRWithTarget {

    /**
     * The priority indicates the SvcPriority.
     * A SvcPriority of 0 puts this RR in AliasMode (otherwise ServiceMode).
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#page-12>SvcPriority</a>
     */
    public final int priority;

    /**
     * A set of key=value pairs (SvcFieldValue).
     * The key is an ID for the parameter.
     *
     * This is a sorted map to follow specification.
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-12.3.2">Possible parameter IDs</a>
     */
    public final Map<SVCBConstants.ServiceKeySpecification, String> params;

    /**
     * @param priority SvcPriority
     * @param target TargetName
     * @param params SvcParams
     */
    public SVCB(int priority, DnsName target, Map<SVCBConstants.ServiceKeySpecification, String> params) {
        super(target);
        this.priority = priority;
        TreeMap<SVCBConstants.ServiceKeySpecification, String> sorted = new TreeMap<>(new Comparator<SVCBConstants.ServiceKeySpecification>() {
            @Override
            public int compare(SVCBConstants.ServiceKeySpecification first, SVCBConstants.ServiceKeySpecification other) {
                return first.getNumber() - other.getNumber(); //Ascending order
            }
        });
        sorted.putAll(params);
        this.params = Collections.unmodifiableSortedMap(sorted);
    }

    /**
     * Parses the wireformat data according to the spec.
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-2.2">RDATA wire format specification</a>
     */
    public static SVCB parse(DataInputStream dis, int length, byte[] data)
            throws IOException {
        int priority = dis.readUnsignedShort();
        DnsName target = DnsName.parse(dis, data);
        Map<SVCBConstants.ServiceKeySpecification, String> params;

        int paramBlobSize = length - 2 - target.getRawBytes().length;
        if(paramBlobSize == 0) {
            params = Collections.emptyMap();
        } else {
            params = parseParamsBlob(dis, paramBlobSize);
        }

        return new SVCB(priority, target, params);
    }

    private static Map<SVCBConstants.ServiceKeySpecification, String> parseParamsBlob(DataInputStream dis, int paramBlobSize) throws IOException {
        int remainingBytes = paramBlobSize;
        int lastKey = Integer.MIN_VALUE;
        Map<SVCBConstants.ServiceKeySpecification, String> params = new LinkedHashMap<>();

        while(remainingBytes > 0) {
            int key = dis.readUnsignedShort();
            String value = null;
            if(key < lastKey) throw new IllegalArgumentException("SVCB ServiceKeys must be in ascending order");
            else if(key == lastKey) throw new IllegalArgumentException("SVCB ServiceKeys must not be duplicate");
            lastKey = key;

            int valueLength = dis.readUnsignedShort();
            if(valueLength != 0) {
                byte[] valueBlob = new byte[valueLength];
                dis.readFully(valueBlob);
                value = new String(valueBlob, StandardCharsets.UTF_8);
            }

            params.put(SVCBConstants.ServiceKey.findFrom(key), value);
            remainingBytes = remainingBytes - 4 - valueLength;
        }
        return Collections.unmodifiableMap(params);
    }

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        dos.writeShort(priority);
        super.serialize(dos);
        for (Map.Entry<SVCBConstants.ServiceKeySpecification, String> entry : params.entrySet()) {
            dos.writeShort(entry.getKey().getNumber());
            byte[] paramValueBlob = entry.getValue().getBytes(StandardCharsets.UTF_8);
            dos.writeShort(paramValueBlob.length);
            dos.write(paramValueBlob);
        }
    }

    @Override
    public Record.TYPE getType() {
        return Record.TYPE.SVCB;
    }

    @Override
    public String toString() {
        return priority + " " + target + createValuesString();
    }

    private String createValuesString() {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<SVCBConstants.ServiceKeySpecification, String> entry : params.entrySet()) {
            builder.append(" ");
            builder.append(entry.getKey().getTextualRepresentation());
            builder.append("=");
            builder.append("\"");
            builder.append(entry.getValue());
            builder.append("\"");
        }
        return builder.toString();
    }
}
