package de.measite.minidns.sec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class JavaSecDigestCalculator implements DigestCalculator {

    private MessageDigest md;

    public JavaSecDigestCalculator(String algorithm) throws NoSuchAlgorithmException {
        md = MessageDigest.getInstance(algorithm);
    }

    @Override
    public byte[] digest(byte[] bytes) {
        return md.digest(bytes);
    }
}
