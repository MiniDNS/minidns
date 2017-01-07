/*
 * Copyright 2015-2016 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.hla;

import de.measite.minidns.DNSName;

public enum SrvService {

    // @formatter:off
    xmpp_client,
    xmpp_server,
    ;
    // @formatter:on

    public final DNSName dnsName;

    SrvService() {
        String enumName = name().replaceAll("_", "-");
        dnsName = DNSName.from('_' + enumName);
    }
}
