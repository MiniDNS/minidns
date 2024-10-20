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
package org.minidns.hla.srv;

import org.minidns.dnslabel.DnsLabel;

public enum SrvService {

    // @formatter:off
    xmpp_client,
    xmpp_server,

    /**
     * XMPP client-to-server (c2s) connections using implicit TLS (also known as "Direct TLS").
     *
     * @see <a href="https://xmpp.org/extensions/xep-0368.html">XEP-0368: SRV records for XMPP over TLS</a>
     */
    xmpps_client,

    /**
     * XMPP server-to-server (s2s) connections using implicit TLS (also known as "Direct TLS").
     *
     * @see <a href="https://xmpp.org/extensions/xep-0368.html">XEP-0368: SRV records for XMPP over TLS</a>
     */
    xmpps_server,
    ;
    // @formatter:on

    @SuppressWarnings("ImmutableEnumChecker")
    public final DnsLabel dnsLabel;

    SrvService() {
        String enumName = name().replaceAll("_", "-");
        dnsLabel = DnsLabel.from('_' + enumName);
    }
}
