package io.github.vssavin.securelib;

import io.github.vssavin.securelib.platformSecure.PlatformSecure;
import io.github.vssavin.securelib.platformSecure.PlatformSecureFactory;
import io.github.vssavin.securelib.platformSecure.PlatformSpecificSecure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class PlatformSpecificSecureImpl implements PlatformSpecificSecure {
    private static final Logger LOG = LoggerFactory.getLogger(PlatformSpecificSecureImpl.class);
    private  static final int GCM_IV_LENGTH = 12;
    private final SecureRandom secureRandom = new SecureRandom();

    private SecretKeySpec secretKey;

    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";

    public PlatformSpecificSecureImpl() {
        prepare();
    }

    @Override
    public String decrypt(String encoded) {
        return decode(encoded);
    }

    @Override
    public String encrypt(String message) {
        return encode(message);
    }

    @Override
    public String decrypt(String encoded, String key) {
        return decode(encoded, key);
    }

    @Override
    public String encrypt(String message, String key) {
        return encode(message, key);
    }

    private void prepare() {
        PlatformSecure platformSecure = PlatformSecureFactory.getPlatformSecurity();
        String key = platformSecure.getSecureKey();
        if (key.isEmpty()) {
            String message = String.format("Error while getting platform security key [%s]", platformSecure);
            LOG.error(message);
            throw new IllegalStateException(message);
        } else {
            setKey(key);
        }
    }

    private void setKey(String myKey) {
        try {
            if (myKey.length() < 16) {
                StringBuilder builder = new StringBuilder(myKey);
                while (builder.length() < 16) {
                    builder.append("0");
                }
                myKey = builder.toString();
            }

            byte[] key = myKey.getBytes(StandardCharsets.UTF_8);
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            synchronized (sha) {
                key = sha.digest(key);
            }

            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (Exception ex) {
            LOG.error("SetKey error: ", ex);
        }
    }

    private String encode(String strToEncrypt) {
        String result = "";
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            synchronized (cipher) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
                byte[] cipherText = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));
                ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
                byteBuffer.put(iv);
                byteBuffer.put(cipherText);
                result = Base64.getEncoder().encodeToString(byteBuffer.array());
            }
        } catch (Exception ex) {
            LOG.error("Encrypt error: ", ex);
        }
        return result;
    }

    private String decode(String strToDecrypt) {
        String result = "";
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            byte[] base64Decoded = Base64.getDecoder().decode(strToDecrypt.getBytes(StandardCharsets.ISO_8859_1));
            AlgorithmParameterSpec gcmIv = new GCMParameterSpec(128, base64Decoded, 0, GCM_IV_LENGTH);
            synchronized (cipher) {
                cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmIv);
                result = new String(cipher.doFinal(base64Decoded, GCM_IV_LENGTH,
                        base64Decoded.length - GCM_IV_LENGTH));
            }
        } catch (Exception e) {
            LOG.error("Decrypt error: ", e);
        }
        return result;
    }

    private String encode(String strToEncrypt, String key) {
        String result = "";
        try {
            setKey(key);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            synchronized (cipher) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
                byte[] cipherText = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));
                ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
                byteBuffer.put(iv);
                byteBuffer.put(cipherText);
                result = Base64.getEncoder().encodeToString(byteBuffer.array());
            }
        } catch (Exception ex) {
            LOG.error("Encrypt error: ", ex);
        }
        return result;
    }

    private String decode(String strToDecrypt, String key) {
        String result = "";
        try {
            setKey(key);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            byte[] base64Decoded = Base64.getDecoder().decode(strToDecrypt.getBytes(StandardCharsets.ISO_8859_1));
            AlgorithmParameterSpec gcmIv = new GCMParameterSpec(128, base64Decoded, 0, GCM_IV_LENGTH);

            synchronized (cipher) {
                cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmIv);
                result = new String(cipher.doFinal(base64Decoded, GCM_IV_LENGTH,
                        base64Decoded.length - GCM_IV_LENGTH));
            }
        } catch (Exception e) {
            LOG.error("Decrypt error: ", e);
        }
        return result;
    }
}
