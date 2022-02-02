package io.github.vssavin.securelib;

import org.junit.Assert;
import org.junit.Test;

public class SecureTest {

    @Test
    public void AESSecureEncryptDecryptTest(){
        String message = "testMessage";
        Secure aesSecure = new AESSecure();
        String aesKey = aesSecure.getSecureKey("test");
        String encrypted = aesSecure.encrypt(message, aesKey);
        String decrypted = aesSecure.decrypt(encrypted, aesKey);

        Assert.assertEquals(message, decrypted);

    }

    @Test
    public void RSASecureEncryptDecryptTest(){
        String message = "testMessage";
        Secure rsaSecure = new RSASecure();
        String rsaKey = rsaSecure.getSecureKey("test");
        String encrypted = rsaSecure.encrypt(message, rsaKey);
        String decrypted = rsaSecure.decrypt(encrypted, rsaKey);

        Assert.assertEquals(message, decrypted);

    }

}
