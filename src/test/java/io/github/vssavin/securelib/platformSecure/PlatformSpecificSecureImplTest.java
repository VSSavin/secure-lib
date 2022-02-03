package io.github.vssavin.securelib.platformSecure;

import io.github.vssavin.securelib.PlatformSpecificSecureImpl;
import org.junit.Assert;
import org.junit.Test;

public class PlatformSpecificSecureImplTest {

    @Test
    public void StorageSecureWithDefaultPlatformSecureTest() {
        String message = "test message";
        PlatformSecure platformSecure = new DefaultPlatformSecure();
        String key = platformSecure.getSecureKey();
        PlatformSpecificSecure storageSecure = new PlatformSpecificSecureImpl();
        String encrypted = storageSecure.encrypt(message, key);
        String decrypted = storageSecure.decrypt(encrypted, key);

        Assert.assertEquals(message, decrypted);
    }

    @Test
    public void StorageSecureWithWindowsPlatformSecureTest() {
        String message = "test message";
        PlatformSecure platformSecure = new WindowsPlatformSecure();
        String key = platformSecure.getSecureKey();
        PlatformSpecificSecure storageSecure = new PlatformSpecificSecureImpl();
        String encrypted = storageSecure.encrypt(message, key);
        String decrypted = storageSecure.decrypt(encrypted, key);

        Assert.assertEquals(message, decrypted);
    }

    @Test
    public void StorageSecureWithLinuxPlatformSecureTest() {
        String message = "test message";
        PlatformSecure platformSecure = new LinuxPlatformSecure();
        String key = platformSecure.getSecureKey();
        PlatformSpecificSecure storageSecure = new PlatformSpecificSecureImpl();
        String encrypted = storageSecure.encrypt(message, key);
        String decrypted = storageSecure.decrypt(encrypted, key);

        Assert.assertEquals(message, decrypted);
    }
}
