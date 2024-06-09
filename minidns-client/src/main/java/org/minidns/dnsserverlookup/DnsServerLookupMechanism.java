/*
 * Copyright 2015-2024 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.dnsserverlookup;

import java.util.List;

public interface DnsServerLookupMechanism extends Comparable<DnsServerLookupMechanism> {

    String getName();

    int getPriority();

    boolean isAvailable();

    /**
     * Returns a List of String representing ideally IP addresses. The list must be modifiable.
     * <p>
     * Note that the lookup mechanisms are not required to assure that only IP addresses are returned. This verification is performed in
     * when using {@link org.minidns.DnsClient#findDNS()}.
     * </p>
     *
     * @return a List of Strings presenting hopefully IP addresses.
     */
    List<String> getDnsServerAddresses();

}
