package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;

/**
 * Generic payload class.
 */
public interface Data {

    /**
     * The payload type.
     * @return The payload type.
     */
    TYPE getType();

    /**
     * Binary representation of this payload.
     * @return The binary representation of this payload.
     */
    byte[] toByteArray();

    /**
     * Parse this payload.
     * @param dis The input stream.
     * @param data The plain data (needed for name cross references).
     * @param length The payload length.
     * @throws IOException on io error (read past paket boundary).
     */
    void parse(DataInputStream dis, byte data[], int length) throws IOException;

}
