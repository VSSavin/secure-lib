package io.github.vssavin.securelib;

import org.junit.Assert;
import org.junit.Test;

public class SecureTest {

    private static final String testMessage = "testMessage";

    @Test
    public void AESSecureEncryptDecryptTest(){
        Secure aesSecure = new AESSecure();
        String aesKey = aesSecure.getSecureKey("test");
        String encrypted = aesSecure.encrypt(testMessage, aesKey);
        String decrypted = aesSecure.decrypt(encrypted, aesKey);

        Assert.assertEquals(testMessage, decrypted);

    }

    @Test
    public void RSASecureEncryptDecryptTest(){
        Secure rsaSecure = new RSASecure();
        String rsaKey = rsaSecure.getSecureKey("test");
        String encrypted = rsaSecure.encrypt(testMessage, rsaKey);
        String decrypted = rsaSecure.decrypt(encrypted, rsaKey);

        Assert.assertEquals(testMessage, decrypted);

    }

    @Test
    public void NOSecureEncryptDecryptTest(){
        Secure rsaSecure = new NoSecure();
        String rsaKey = rsaSecure.getSecureKey("test");
        String encrypted = rsaSecure.encrypt(testMessage, rsaKey);
        String decrypted = rsaSecure.decrypt(encrypted, rsaKey);

        Assert.assertEquals(testMessage, decrypted);

    }

}
