package io.github.vssavin.securelib;

/**
 * Created by vssavin on 17.05.2022.
 */
public class NoSecure implements Secure {

    private static final String ENCRYPT_METHOD_NAME_FOR_VIEW = Secure.getEncryptionMethodName(SecureAlgorithm.NOSECURE);

    @Override
    public String getSecureKey(String s) {
        return "";
    }

    @Override
    public String decrypt(String encoded, String key) {
        return encoded;
    }

    @Override
    public String encrypt(String message, String key) {
        return message;
    }

    @Override
    public String getEncryptMethodNameForView() {
        return ENCRYPT_METHOD_NAME_FOR_VIEW;
    }
}
