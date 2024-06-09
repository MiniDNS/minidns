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
package org.minidns.source;

import org.minidns.MiniDnsException;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsqueryresult.DnsQueryResult.QueryMethod;
import org.minidns.dnsqueryresult.StandardDnsQueryResult;
import org.minidns.util.MultipleIoException;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class NetworkDataSource extends AbstractDnsDataSource {

    protected static final Logger LOGGER = Logger.getLogger(NetworkDataSource.class.getName());

    // TODO: Rename 'message' parameter to query.
    @Override
    public StandardDnsQueryResult query(DnsMessage message, InetAddress address, int port) throws IOException {
        final QueryMode queryMode = getQueryMode();
        boolean doUdpFirst;
        switch (queryMode) {
        case dontCare:
        case udpTcp:
            doUdpFirst = true;
            break;
        case tcp:
            doUdpFirst = false;
            break;
        default:
            throw new IllegalStateException("Unsupported query mode: " + queryMode);
        }

        List<IOException> ioExceptions = new ArrayList<>(2);
        DnsMessage dnsMessage = null;

        if (doUdpFirst) {
            try {
                dnsMessage = queryUdp(message, address, port);
            } catch (IOException e) {
                ioExceptions.add(e);
            }

            // TODO: This null check could probably be removed by now.
            if (dnsMessage != null && !dnsMessage.truncated) {
                return new StandardDnsQueryResult(address, port, QueryMethod.udp, message, dnsMessage);
            }

            assert dnsMessage == null || dnsMessage.truncated || ioExceptions.size() == 1;
            LOGGER.log(Level.FINE, "Fallback to TCP because {0}",
                    new Object[] { dnsMessage != null ? "response is truncated" : ioExceptions.get(0) });
        }

        try {
            dnsMessage = queryTcp(message, address, port);
        } catch (IOException e) {
            ioExceptions.add(e);
            MultipleIoException.throwIfRequired(ioExceptions);
        }

        return new StandardDnsQueryResult(address, port, QueryMethod.tcp, message, dnsMessage);
    }

    protected DnsMessage queryUdp(DnsMessage message, InetAddress address, int port) throws IOException {
        // TODO Use a try-with-resource statement here once miniDNS minimum
        // required Android API level is >= 19
        DatagramSocket socket = null;
        DatagramPacket packet = message.asDatagram(address, port);
        byte[] buffer = new byte[udpPayloadSize];
        try {
            socket = createDatagramSocket();
            socket.setSoTimeout(timeout);
            socket.send(packet);
            packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);
            DnsMessage dnsMessage = new DnsMessage(packet.getData());
            if (dnsMessage.id != message.id) {
                throw new MiniDnsException.IdMismatch(message, dnsMessage);
            }
            return dnsMessage;
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    protected DnsMessage queryTcp(DnsMessage message, InetAddress address, int port) throws IOException {
        // TODO Use a try-with-resource statement here once miniDNS minimum
        // required Android API level is >= 19
        Socket socket = null;
        try {
            socket = createSocket();
            SocketAddress socketAddress = new InetSocketAddress(address, port);
            socket.connect(socketAddress, timeout);
            socket.setSoTimeout(timeout);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            message.writeTo(dos);
            dos.flush();
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            int length = dis.readUnsignedShort();
            byte[] data = new byte[length];
            int read = 0;
            while (read < length) {
                read += dis.read(data, read, length - read);
            }
            DnsMessage dnsMessage = new DnsMessage(data);
            if (dnsMessage.id != message.id) {
                throw new MiniDnsException.IdMismatch(message, dnsMessage);
            }
            return dnsMessage;
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    /**
     * Create a {@link Socket} using the system default {@link javax.net.SocketFactory}.
     *
     * @return The new {@link Socket} instance
     */
    protected Socket createSocket() {
        return new Socket();
    }

    /**
     * Create a {@link DatagramSocket} using the system defaults.
     *
     * @return The new {@link DatagramSocket} instance
     * @throws SocketException If creation of the {@link DatagramSocket} fails
     */
    protected DatagramSocket createDatagramSocket() throws SocketException {
        return new DatagramSocket();
    }
}
