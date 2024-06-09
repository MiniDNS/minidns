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

/**
 *  The Serivce and Protocol part of a SRV owner name. The format of a SRV owner name is "_Service._Proto.Name".
 */
public class SrvServiceProto {

    public final DnsLabel service;
    public final DnsLabel proto;

    public SrvServiceProto(DnsLabel service, DnsLabel proto) {
        this.service = service;
        this.proto = proto;
    }
}
