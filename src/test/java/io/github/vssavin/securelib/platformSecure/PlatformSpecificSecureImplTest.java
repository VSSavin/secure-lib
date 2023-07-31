package io.github.vssavin.securelib.platformSecure;

import io.github.vssavin.securelib.PlatformSpecificSecureImpl;
import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class PlatformSpecificSecureImplTest {

    @Test
    public void StorageSecureWithDefaultPlatformSecureConcurrentTest() {
        PlatformSecure platformSecure = new DefaultPlatformSecure();
        PlatformSpecificSecure platformSpecificSecure = new PlatformSpecificSecureImpl();

        Throwable throwable = null;

        try {
            secureConcurrentTest(platformSecure, platformSpecificSecure);
        } catch (ExecutionException e) {
            e.printStackTrace();
            throwable = e;
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Assert.assertNull(throwable);
    }

    @Test
    public void StorageSecureWithWindowsPlatformSecureConcurrentTest() {
        PlatformSecure platformSecure = new WindowsPlatformSecure();
        PlatformSpecificSecure platformSpecificSecure = new PlatformSpecificSecureImpl();

        Throwable throwable = null;

        try {
            secureConcurrentTest(platformSecure, platformSpecificSecure);
        } catch (ExecutionException e) {
            e.printStackTrace();
            throwable = e;
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Assert.assertNull(throwable);
    }

    @Test
    public void StorageSecureWithLinuxPlatformSecureConcurrentTest() {
        PlatformSecure platformSecure = new LinuxPlatformSecure();
        PlatformSpecificSecure platformSpecificSecure = new PlatformSpecificSecureImpl();

        Throwable throwable = null;

        try {
            secureConcurrentTest(platformSecure, platformSpecificSecure);
        } catch (ExecutionException e) {
            e.printStackTrace();
            throwable = e;
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Assert.assertNull(throwable);
    }

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

    private void secureConcurrentTest(PlatformSecure platformSecure, PlatformSpecificSecure platformSpecificSecure)
            throws ExecutionException, InterruptedException {
        String key = platformSecure.getSecureKey();
        final int threadsCount = 10;

        List<CompletableFuture<Void>> futures = new ArrayList<>();
        Map<String, String> encryptedMap = new ConcurrentHashMap<>();
        List<String> messages = new CopyOnWriteArrayList<>();

        CountDownLatch latch = new CountDownLatch(1);

        for(int i = 0; i < threadsCount; i++) {
            futures.add(CompletableFuture.runAsync(() -> {
                try {
                    latch.await();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                String message = randomString();
                String encrypted = platformSpecificSecure.encrypt(message, key);
                encryptedMap.put(message, encrypted);
                messages.add(message);
            }));
        }

        CompletableFuture<?>[] futuresArray = futures.toArray(new CompletableFuture[0]);
        latch.countDown();
        CompletableFuture.allOf(futuresArray).get();

        futures.clear();
        CountDownLatch latch2 = new CountDownLatch(1);
        for (int i = 0; i < threadsCount; i++) {
            String message = messages.get(i);
            futures.add(CompletableFuture.runAsync(() -> {
                try {
                    latch2.await();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                platformSpecificSecure.decrypt(encryptedMap.get(message), key);
            }));
        }

        futuresArray = futures.toArray(new CompletableFuture[0]);

        latch2.countDown();

        CompletableFuture.allOf(futuresArray).get();
    }

    private String randomString() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();
        return IntStream.range(0, 20)
                .map(i -> random.nextInt(chars.length()))
                .mapToObj(randomIndex -> String.valueOf(chars.charAt(randomIndex)))
                .collect(Collectors.joining());
    }
}
