package org.minidns.record;

import org.minidns.dnsname.DnsName;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SVCB Record Type (Service binding)
 *
 * https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-01
 */
class SVCB extends RRWithTarget {

    /**
     * The priority indicates the SvcRecordType.
     * https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-01#section-2.4
     */
    public final int priority;

    /**
     * SvcFieldValue
     * A set of key=value pairs.
     * https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-01#section-2.1
     */
    public final Map<String, String> values;

    // The first group is the key. They key can only be a-z, 0-9 or "-"
    // The second group is the value. It can be a lot of things (see https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-01#section-2.1.1)
    //    except for DQUOTE (hence it can be excluded from the regex-group)
    private static final Pattern valuesPattern = Pattern.compile("([a-z0-9\\-]+)=\"([^\"]*)\"");

    /**
     * @param priority SvcRecordType
     * @param target SvcDomainName
     * @param values SvcFieldValue
     */
    public SVCB(int priority, DnsName target, Map<String, String> values) {
        super(target);
        this.priority = priority;
        this.values = values;
    }

    public static SVCB parse(DataInputStream dis, int length, byte[] data)
            throws IOException {
        int priority = dis.readUnsignedShort();
        DnsName target = DnsName.parse(dis, data);

        byte[] valuesBlob = new byte[length - 2 - target.getRawBytes().length];
        dis.readFully(valuesBlob);
        return new SVCB(priority, target, parseValuesBlob(valuesBlob));
    }

    /**
     * Parses pairs according to format from https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-01#section-2.1.1
     */
    private static Map<String, String> parseValuesBlob(byte[] blob) {
        Map<String, String> values = new LinkedHashMap<>();
        String blobAsString = new String(blob, StandardCharsets.UTF_8);
        Matcher matcher = valuesPattern.matcher(blobAsString);
        while(matcher.find()) {
            values.put(matcher.group(1), matcher.group(2));
        }
        return values;
    }

    @Override
    public Record.TYPE getType() {
        return Record.TYPE.SVCB;
    }

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        dos.writeShort(priority);
        super.serialize(dos);
        dos.write(createValuesString().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String toString() {
        return priority + " " + target + createValuesString();
    }

    private String createValuesString() {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            builder.append(" ");
            builder.append(entry.getKey());
            builder.append("=");
            builder.append("\"");
            builder.append(entry.getValue());
            builder.append("\"");
        }
        return builder.toString();
    }
}
