package io.github.vssavin.securelib;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class RSASecure implements Secure {
    private static final Logger LOG = LoggerFactory.getLogger(RSASecure.class);
    private static final int EXPIRATION_KEY_SECONDS = 60;
    private static final Map<String, SecureParams> cache = new ConcurrentHashMap<>();
    private static KeyPairGenerator keyPairGenerator = null;
    private static Cipher rsaCipher = null;
    private static KeyFactory keyFactory = null;
    private final String ENCRYPT_METHOD_NAME_FOR_VIEW = Secure.getEncryptionMethodName(SecureAlgorithm.RSA);

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            rsaCipher = Cipher.getInstance("RSA");
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            LOG.error("Key pair generator initialize error: ", e);
        }
    }

    @Override
    public String getSecureKey(String id) {
        SecureParams secureParams = cache.get(id);
        String publicKey = "";
        if (secureParams == null || secureParams.isExpired()) {
            try {
                keyPairGenerator.initialize(2048);
                KeyPair pair = keyPairGenerator.generateKeyPair();
                byte[] publicKeyBytes = pair.getPublic().getEncoded();
                byte[] privateKeyBytes = pair.getPrivate().getEncoded();
                publicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
                String privateKey = Base64.getEncoder().encodeToString(privateKeyBytes);
                secureParams = new SecureParams(id, publicKey, privateKey);
                cache.put(id, secureParams);
            } catch (Exception e) {
                LOG.error("Getting secure key error: ", e);
            }

        } else {
            publicKey = secureParams.getPublicKey();
        }
        return publicKey;
    }

    @Override
    public String decrypt(String encoded, String publicKey) {
        String decrypted = "";
        try {
            String privateKeyString = getPrivateKeyByPublicKey(publicKey);
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString.getBytes());
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            decrypted = new String(rsaCipher.doFinal(Base64.getDecoder().decode(encoded.getBytes())));
        } catch (InvalidKeySpecException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException e) {
            LOG.error("Decrypting error: ", e);
        }

        return decrypted;
    }

    @Override
    public String encrypt(String message, String publicKeyString) {
        publicKeyString = normalizeKey(publicKeyString);

        Cipher encryptCipher;
        String encrypted = "";
        try {
            encryptCipher = Cipher.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString.getBytes()));
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encrypted = new String(Base64.getEncoder().encode(encryptCipher.doFinal(message.getBytes())));
        } catch (Exception e) {
            LOG.error("Encrypting error: ", e);
        }

        return encrypted;
    }

    @Override
    public String getEncryptMethodNameForView() {
        return ENCRYPT_METHOD_NAME_FOR_VIEW;
    }

    private String normalizeKey(String key) {
        if (key != null) {
            String commentSeparator = "-----";
            key = key.replaceAll(System.lineSeparator(), "");
            String[] strings = key.split(commentSeparator);
            for(int i = 0; i < strings.length; i++) {
                if (strings[i].isEmpty()) i++;
                else {
                    key = strings[i];
                    break;
                }
            }
        }

        return key;
    }

    private String getPrivateKeyByPublicKey(String pulbicKey) {
        List<SecureParams> filtered = cache.values().stream()
                .filter(secureParams -> secureParams.getPublicKey().equals(pulbicKey)).collect(Collectors.toList());
        return filtered.size() > 0 ? filtered.get(0).getPrivateKey() : "";
    }

    private class SecureParams {
        private String address;
        private String publicKey;
        private String privateKey;
        private Date expiration;

        SecureParams(String address, String publicKey, String privateKey) {
            this.address = address;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.expiration = new Date(System.currentTimeMillis() + EXPIRATION_KEY_SECONDS * 1000);
        }

        boolean isExpired() {
            return new Date().after(expiration);
        }

        String getPublicKey() {
            return publicKey;
        }

        String getPrivateKey() {
            return privateKey;
        }

        String getAddress() {
            return address;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            SecureParams that = (SecureParams) o;

            if (!address.equals(that.address)) return false;
            if (!publicKey.equals(that.publicKey)) return false;
            if (!privateKey.equals(that.privateKey)) return false;
            return expiration.equals(that.expiration);
        }

        @Override
        public int hashCode() {
            int result = address.hashCode();
            result = 31 * result + publicKey.hashCode();
            result = 31 * result + privateKey.hashCode();
            result = 31 * result + expiration.hashCode();
            return result;
        }
    }
}
