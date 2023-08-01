package io.github.vssavin.securelib;

import io.github.vssavin.securelib.platformSecure.PlatformSecure;
import io.github.vssavin.securelib.platformSecure.PlatformSecureFactory;
import io.github.vssavin.securelib.platformSecure.PlatformSpecificSecure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class PlatformSpecificSecureImpl implements PlatformSpecificSecure {
    private static final Logger LOG = LoggerFactory.getLogger(PlatformSpecificSecureImpl.class);
    private SecretKeySpec secretKey;

    private static final String ENCRYPTION_ALGORITHM = "AES/ECB/PKCS5Padding";

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
            synchronized (cipher) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                result = Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
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
            synchronized (cipher) {
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                result = new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
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
            synchronized (cipher) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                result = Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
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
            synchronized (cipher) {
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                result = new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
            }
        } catch (Exception e) {
            LOG.error("Decrypt error: ", e);
        }
        return result;
    }
}
