package de.measite.minidns.util;

public class PlatformDetection {

    private static Boolean android;

    public static boolean isAndroid() {
        if (android == null) {
            try {
                Class.forName("android.Manifest"); // throws execption when not on Android
                android = true;
            } catch (Exception e) {
                android = false;
            }
        }
        return android;
    }
}
