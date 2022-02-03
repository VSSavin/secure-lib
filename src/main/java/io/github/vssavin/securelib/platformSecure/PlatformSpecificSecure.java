package io.github.vssavin.securelib.platformSecure;

public interface PlatformSpecificSecure {
    String decrypt(String encoded);
    String encrypt(String message);

    String decrypt(String encoded, String key);
    String encrypt(String message, String key);
}
