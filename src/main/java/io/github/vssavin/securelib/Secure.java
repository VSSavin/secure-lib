package io.github.vssavin.securelib;

/**
 * @author vssavin on 01.02.22
 */
public interface Secure {

    enum SecureAlgorithm {
        AES,
        RSA
    }

    static String getEncryptionMethodName(SecureAlgorithm secureAlgorithm) {
        return "encode" + secureAlgorithm.name();
    }

    static String getDecryptionMethodName(SecureAlgorithm secureAlgorithm) {
        return "decode" + secureAlgorithm.name();
    }

    String getSecureKey(String id);
    String decrypt(String encoded, String key);
    String encrypt(String message, String key);
    String getEncryptMethodNameForView();
}
