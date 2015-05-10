package de.measite.minidns.record;

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

}
