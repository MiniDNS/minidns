package de.measite.minidns.sec;

import java.security.NoSuchAlgorithmException;

public interface DigestCalculator {
    byte[] digest(byte[] bytes);
}
