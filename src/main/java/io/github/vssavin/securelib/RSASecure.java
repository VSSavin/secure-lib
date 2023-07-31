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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class RSASecure implements Secure {
    private static final Logger LOG = LoggerFactory.getLogger(RSASecure.class);
    private static int expirationKeySeconds = 60;
    private static final Map<String, SecureParams> cache = new ConcurrentHashMap<>();
    private final KeyPairGenerator keyPairGenerator;
    private final Cipher rsaCipher;
    private final KeyFactory keyFactory;
    private final String ENCRYPT_METHOD_NAME_FOR_VIEW = Secure.getEncryptionMethodName(SecureAlgorithm.RSA);

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public RSASecure() {
        KeyFactory keyFactory1;
        Cipher rsaCipher1;
        KeyPairGenerator keyPairGenerator1;
        try {
            keyPairGenerator1 = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            keyPairGenerator1 = null;
        }

        keyPairGenerator = keyPairGenerator1;
        try {
            rsaCipher1 = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            rsaCipher1 = null;
        }

        rsaCipher = rsaCipher1;

        try {
            keyFactory1 = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            keyFactory1 = null;
        }

        keyFactory = keyFactory1;
    }

    public static void setExpirationKeySeconds(int expirationKeySeconds) {
        RSASecure.expirationKeySeconds = expirationKeySeconds;
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
        String decrypted;
        try {
            String privateKeyString = getPrivateKeyByPublicKey(publicKey);
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString.getBytes());
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            synchronized (rsaCipher) {
                rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            }

            byte[] base64 = Base64.getDecoder().decode(encoded.getBytes());
            byte[] decryptedBytes;
            synchronized (rsaCipher) {
                decryptedBytes = rsaCipher.doFinal(base64);
            }

            Arrays.fill(base64, (byte)0);
            decrypted = new String(decryptedBytes);
            Arrays.fill(decryptedBytes, (byte)0);
        } catch (InvalidKeySpecException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException e) {
            String errorMessage = "Decryption error!";
            LOG.error(errorMessage, e);
            throw new EncryptionException(errorMessage, e);
        }

        return decrypted;
    }

    @Override
    public String encrypt(String message, String publicKeyString) {
        if (publicKeyString == null) return message;
        publicKeyString = normalizeKey(publicKeyString);

        Cipher encryptCipher;
        String encrypted;
        try {
            encryptCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString.getBytes()));
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = encryptCipher.doFinal(message.getBytes());
            byte[] base64 = Base64.getEncoder().encode(encryptedBytes);
            Arrays.fill(encryptedBytes, (byte) 0);
            encrypted = new String(base64);
            Arrays.fill(base64, (byte) 0);

        } catch (Exception e) {
            String errorMessage = "Encryption error!";
            LOG.error(errorMessage, e);
            throw new EncryptionException(errorMessage, e);
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
        return !filtered.isEmpty() ? filtered.get(0).getPrivateKey() : "";
    }

    private static class SecureParams {
        private final String address;
        private final String publicKey;
        private final String privateKey;
        private final Date expiration;

        SecureParams(String address, String publicKey, String privateKey) {
            this.address = address;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.expiration = new Date(System.currentTimeMillis() + expirationKeySeconds * 1000L);
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
