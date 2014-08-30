package de.measite.minidns.record;

import java.io.DataInputStream;
import java.io.IOException;

import de.measite.minidns.Record.TYPE;

/**
 * TXT record (actually a binary blob with wrappers for text content).
 */
public class TXT implements Data {

    protected final byte[] blob;

    public TXT(DataInputStream dis, byte[] data, int length) throws IOException {
        blob = new byte[length];
        dis.readFully(blob);
    }

    public TXT(String text) {
        try {
            this.blob = text.getBytes("UTF-8");
        } catch (Exception e) {
            /* Can't happen, UTF-8 IS supported */
            throw new RuntimeException("UTF-8 not supported", e);
        }
    }
 
    public TXT(byte[] blob) {
        this.blob = blob;
    }

    public byte[] getBlob() {
        return blob;
    }

    public String getText() {
        try {
            return (new String(blob, "UTF-8")).intern();
        } catch (Exception e) {
            /* Can't happen for UTF-8 unless it's really a blob */
            return null;
        }
    }

    @Override
    public byte[] toByteArray() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public TYPE getType() {
        return TYPE.TXT;
    }

    @Override
    public String toString() {
        return "\"" + getText() + "\"";
    }

}
