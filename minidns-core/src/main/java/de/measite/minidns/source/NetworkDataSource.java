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
package de.measite.minidns.source;

import de.measite.minidns.DNSMessage;
import de.measite.minidns.MiniDNSException;
import de.measite.minidns.util.MultipleIoException;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class NetworkDataSource extends DNSDataSource {

    protected static final Logger LOGGER = Logger.getLogger(NetworkDataSource.class.getName());

    public DNSMessage query(DNSMessage message, InetAddress address, int port) throws IOException {
        List<IOException> ioExceptions = new ArrayList<>(2);
        DNSMessage dnsMessage = null;
        try {
            dnsMessage = queryUdp(message, address, port);
        } catch (IOException e) {
            ioExceptions.add(e);
        }

        if (dnsMessage != null && !dnsMessage.isTruncated()) {
            return dnsMessage;
        }

        try {
            dnsMessage = queryTcp(message, address, port);
        } catch (IOException e) {
            ioExceptions.add(e);
            MultipleIoException.throwIfRequired(ioExceptions);
        }

        if (dnsMessage != null && !ioExceptions.isEmpty()) {
            // In this case, there can only be one exception.
            assert(ioExceptions.size() == 1);
            LOGGER.log(Level.FINE, "IO Exception while asking for " + message, ioExceptions.get(0));
        }

        return dnsMessage;
    }

    protected DNSMessage queryUdp(DNSMessage message, InetAddress address, int port) throws IOException {
        byte[] buf = message.toArray();
        // TODO Use a try-with-resource statement here once miniDNS minimum
        // required Android API level is >= 19
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            DatagramPacket packet = new DatagramPacket(buf, buf.length,
                    address, port);
            socket.setSoTimeout(timeout);
            socket.send(packet);
            packet = new DatagramPacket(new byte[bufferSize], bufferSize);
            socket.receive(packet);
            DNSMessage dnsMessage = new DNSMessage(packet.getData());
            if (dnsMessage.getId() != message.getId()) {
                throw new MiniDNSException.IdMismatch(message, dnsMessage);
            }
            return dnsMessage;
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    protected DNSMessage queryTcp(DNSMessage message, InetAddress address, int port) throws IOException {
        byte[] buf = message.toArray();
        // TODO Use a try-with-resource statement here once miniDNS minimum
        // required Android API level is >= 19
        Socket socket = null;
        try {
            socket = new Socket(address, port);
            socket.setSoTimeout(timeout);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            dos.writeShort(buf.length);
            dos.write(buf);
            dos.flush();
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            int length = dis.readUnsignedShort();
            byte[] data = new byte[length];
            int read = 0;
            while (read < length) {
                read += dis.read(data, read, length-read);
            }
            DNSMessage dnsMessage = new DNSMessage(data);
            if (dnsMessage.getId() != message.getId()) {
                throw new MiniDNSException.IdMismatch(message, dnsMessage);
            }
            return dnsMessage;
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }
}
