package org.minidns.constants;

public class SVCBConstants {
    public interface ServiceKeySpecification {
        int getNumber();
        String getTextualRepresentation();
    }

    public enum ServiceKey implements ServiceKeySpecification {
        MANDATORY(0, "mandatory"),
        ALPN(1, "alpn"),
        NO_DEFAULT_ALPN(2, "no-default-alpn"),
        PORT(3, "port"),
        IPV4HINT(4, "ipv4hint"),
        ECHOCONFIG(5, "echoconfig"),
        IPV6HINT(6, "ipv6hint"),
        INVALID_KEY(65535, "key65535");

        private final int number;
        private final String name;
        ServiceKey(int number, String name) {
            this.number = number;
            this.name = name;
        }

        @Override
        public int getNumber() {
            return number;
        }

        @Override
        public String getTextualRepresentation() {
            return name;
        }

        public static ServiceKeySpecification findFrom(int number) {
            for (ServiceKey value : values()) {
                if(value.number == number) return value;
            }
            return new UnrecognizedServiceKey(number);
        }
    }

    public static final class UnrecognizedServiceKey implements ServiceKeySpecification {
        private final int number;

        public UnrecognizedServiceKey(int number) {
            this.number = number;
        }

        @Override
        public int getNumber() {
            return number;
        }

        @Override
        public String getTextualRepresentation() {
            return String.valueOf(number);
        }

        @Override
        public String toString() {
            return "key" + number;
        }
    }
}
