package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;

public interface Data {

    TYPE getType();

    byte[] toByteArray();

    void parse(DataInputStream dis, byte data[], int length) throws IOException;

}
