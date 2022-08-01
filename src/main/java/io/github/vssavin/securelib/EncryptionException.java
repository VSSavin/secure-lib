package io.github.vssavin.securelib;

/**
 * Created by vssavin on 01.08.2022.
 */
public class EncryptionException extends RuntimeException{
    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
