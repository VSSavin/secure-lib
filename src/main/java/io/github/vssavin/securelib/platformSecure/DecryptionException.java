package io.github.vssavin.securelib.platformSecure;

/**
 * Created by vssavin on 01.08.2023
 */
public class DecryptionException extends RuntimeException {
    public DecryptionException(String message) {
        super(message);
    }

    public DecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
