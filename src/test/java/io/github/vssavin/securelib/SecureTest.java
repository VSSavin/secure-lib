package io.github.vssavin.securelib;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

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

    private void secureConcurrentTest(Secure secure) throws ExecutionException, InterruptedException {
        String key = secure.getSecureKey(secure.toString());
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
                String encrypted = secure.encrypt(message, key);
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
                secure.decrypt(encryptedMap.get(message), key);
            }));
        }

        futuresArray = futures.toArray(new CompletableFuture[0]);

        latch2.countDown();

        CompletableFuture.allOf(futuresArray).get();
    }

    @Test
    public void AESSecureConcurrentTest() {
        Secure aesSecure = new AESSecure();
        Throwable throwable = null;

        try {
            secureConcurrentTest(aesSecure);
        } catch (ExecutionException e) {
            e.printStackTrace();
            throwable = e;
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Assert.assertNull(throwable);
    }

    @Test
    public void RSASecureConcurrentTest() {
        Secure aesSecure = new RSASecure();
        Throwable throwable = null;

        try {
            secureConcurrentTest(aesSecure);
        } catch (ExecutionException e) {
            e.printStackTrace();
            throwable = e;
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Assert.assertNull(throwable);
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

    private String randomString() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();
        return IntStream.range(0, 20)
                .map(i -> random.nextInt(chars.length()))
                .mapToObj(randomIndex -> String.valueOf(chars.charAt(randomIndex)))
                .collect(Collectors.joining());
    }

}
