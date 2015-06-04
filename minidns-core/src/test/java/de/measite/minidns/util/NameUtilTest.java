package de.measite.minidns.util;

import static org.junit.Assert.*;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

public class NameUtilTest {
    @Test
    public void sizeTest() {
        assertEquals(1, NameUtil.size(""));
        assertEquals(13, NameUtil.size("example.com"));
        assertEquals(16, NameUtil.size("dömäin"));
        assertEquals(24, NameUtil.size("dömäin.example"));
    }

    @Test
    public void idnEqualsTest() {
        assertTrue(NameUtil.idnEquals(null, null));
        assertTrue(NameUtil.idnEquals("domain.example", "domain.example"));
        assertTrue(NameUtil.idnEquals("dömäin.example", "xn--dmin-moa0i.example"));
        assertTrue(NameUtil.idnEquals("موقع.وزارة-الاتصالات.مصر", "xn--4gbrim.xn----ymcbaaajlc6dj7bxne2c.xn--wgbh1c"));

        assertFalse(NameUtil.idnEquals("dömäin.example", null));
        assertFalse(NameUtil.idnEquals(null, "domain.example"));
        assertFalse(NameUtil.idnEquals("dömäin.example", "domain.example"));
        assertFalse(NameUtil.idnEquals("", "domain.example"));
    }

    @Test
    public void toByteArrayTest() {
        assertArrayEquals(new byte[]{0}, NameUtil.toByteArray(""));
        assertArrayEquals(new byte[]{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}, NameUtil.toByteArray("example"));
        assertArrayEquals(new byte[]{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, NameUtil.toByteArray("example.com"));
        assertArrayEquals(new byte[]{14, 'x', 'n', '-', '-', 'd', 'm', 'i', 'n', '-', 'm', 'o', 'a', '0', 'i', 0}, NameUtil.toByteArray("dömäin"));
    }

    @Test
    public void parseTest() throws IOException {
        byte[] test = new byte[]{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0};
        assertEquals("example", NameUtil.parse(new DataInputStream(new ByteArrayInputStream(test)), test));
        test = new byte[]{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
        assertEquals("example.com", NameUtil.parse(new DataInputStream(new ByteArrayInputStream(test)), test));
    }
    
    @Test
    public void parseWithOffsetTest() {
        // TODO
    }
}
