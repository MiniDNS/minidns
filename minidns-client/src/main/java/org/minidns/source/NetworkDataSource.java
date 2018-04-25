/*
 * Copyright 2015-2018 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.source;

import org.minidns.MiniDNSException;
import org.minidns.dnsmessage.DNSMessage;
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

public class NetworkDataSource extends DNSDataSource {
    private boolean closeSocketAfterQuery = true;
    protected static final Logger LOGGER = Logger.getLogger(NetworkDataSource.class.getName());

    @Override
    public DNSMessage query(DNSMessage message, InetAddress address, int port) throws IOException {
        List<IOException> ioExceptions = new ArrayList<>(2);
        DNSMessage dnsMessage = null;
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

        if (doUdpFirst) {
            try {
                dnsMessage = queryUdp(message, address, port);
            } catch (IOException e) {
                ioExceptions.add(e);
            }

            if (dnsMessage != null && !dnsMessage.truncated) {
                return dnsMessage;
            }

            assert (dnsMessage == null || dnsMessage.truncated || ioExceptions.size() == 1);
            LOGGER.log(Level.FINE, "Fallback to TCP because {0}",
                    new Object[] { dnsMessage != null ? "response is truncated" : ioExceptions.get(0) });
        }

        try {
            dnsMessage = queryTcp(message, address, port);
        } catch (IOException e) {
            ioExceptions.add(e);
            MultipleIoException.throwIfRequired(ioExceptions);
        }

        return dnsMessage;
    }

    protected DNSMessage queryUdp(DNSMessage message, InetAddress address, int port) throws IOException {
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
            DNSMessage dnsMessage = new DNSMessage(packet.getData());
            if (dnsMessage.id != message.id) {
                throw new MiniDNSException.IdMismatch(message, dnsMessage);
            }
            return dnsMessage;
        } finally {
            if (socket != null && shouldCloseSocketAfterQuery()) {
                socket.close();
            }
        }
    }

    protected DNSMessage queryTcp(DNSMessage message, InetAddress address, int port) throws IOException {
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
                read += dis.read(data, read, length-read);
            }
            DNSMessage dnsMessage = new DNSMessage(data);
            if (dnsMessage.id != message.id) {
                throw new MiniDNSException.IdMismatch(message, dnsMessage);
            }
            return dnsMessage;
        } finally {
            if (socket != null && shouldCloseSocketAfterQuery()) {
                socket.close();
            }
        }
    }

    public void setCloseSocketAfterQuery(boolean closeSocketAfterQuery) {
        this.closeSocketAfterQuery = closeSocketAfterQuery;
    }

    public boolean shouldCloseSocketAfterQuery() {
        return closeSocketAfterQuery;
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
