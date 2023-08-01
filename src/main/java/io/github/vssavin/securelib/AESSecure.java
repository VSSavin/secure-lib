package io.github.vssavin.securelib;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class AESSecure implements Secure {
    private static final Logger LOG = LoggerFactory.getLogger(AESSecure.class);
    private static final int EXPIRATION_KEY_SECONDS = 60;
    private static final ScriptEngine engine = new ScriptEngineManager().getEngineByExtension("js");
    private static final Map<String, SecureParams> cache = new ConcurrentHashMap<>();
    private final String ENCRYPT_METHOD_NAME_FOR_VIEW = Secure.getEncryptionMethodName(SecureAlgorithm.AES);
    private final String DECRYPT_METHOD_NAME_FOR_VIEW = Secure.getDecryptionMethodName(SecureAlgorithm.AES);

    static {
        loadScriptsFromResources();
        for (String script : getAdditionalScripts()) {
            try {
                engine.eval(script);
            } catch (ScriptException e) {
                LOG.error("Evaluating js script error: ", e);
            }
        }
    }

    @Override
    public String getSecureKey(String id) {

        SecureParams secureParams = cache.get(id);
        String uuid;
        if (secureParams == null || secureParams.isExpired()) {
            uuid = UUID.randomUUID().toString().replace("-", "");
            secureParams = new SecureParams(id, uuid);
            cache.put(id, secureParams);
        } else {
            uuid = secureParams.getSecureKey();
        }
        return uuid;
    }

    @Override
    public String decrypt(String encoded, String key) {
        String decrypted = "";

        try {
            if (key != null) {
                String scriptForKey = getScriptForKey(key);
                Object result;
                synchronized (engine) {
                    engine.eval(scriptForKey);
                    Invocable invocable = (Invocable) engine;
                    result = invocable.invokeFunction(DECRYPT_METHOD_NAME_FOR_VIEW, encoded, key);
                }

                if (result != null) {
                    String decryptedResult = result.toString();
                    decrypted = decryptedResult.replace("\0", "");
                    if (!Objects.equals(decryptedResult, decrypted)) {
                        Utils.clearString(decryptedResult);
                    }
                }
            }

        } catch (ScriptException | NoSuchMethodException e) {
            LOG.error("JS processing error: ", e);
        }

        return decrypted;
    }

    @Override
    public String encrypt(String message, String key) {
        String encrypted = "";

        try {
            if (message != null && key != null) {
                String scriptForKey = getScriptForKey(key);
                Object result;
                synchronized (engine) {
                    engine.eval(scriptForKey);
                    Invocable invocable = (Invocable) engine;
                    result = invocable.invokeFunction(ENCRYPT_METHOD_NAME_FOR_VIEW, message);
                }

                if (result != null) {
                    String encryptedResult = result.toString();
                    encrypted = encryptedResult.replace("\0", "");
                    if (!Objects.equals(encryptedResult, encrypted)) {
                        Utils.clearString(encryptedResult);
                    }
                }
            }

        } catch (ScriptException | NoSuchMethodException e) {
            LOG.error("JS processing error: ", e);
        }

        return encrypted;
    }

    @Override
    public String getEncryptMethodNameForView() {
        return ENCRYPT_METHOD_NAME_FOR_VIEW;
    }

    private static List<String> getJavaScriptsListFromResources() {
        List<String> list = new ArrayList<>();
        list.add("static/js/AES.js");
        list.add("static/js/crypt.js");
        return list;
    }

    private static List<String> getAdditionalScripts() {
        List<String> list = new ArrayList<>();
        String btoa = "btoa = function(str) {\n" +
                "\treturn java.util.Base64.encoder.encodeToString(str.bytes);" +
                "}";

        String atob = "atob = function(str) {\n" +
                "\treturn java.util.Base64.decoder.decode(str);" +
                "}";

        list.add(btoa);
        list.add(atob);
        return list;
    }

    private static void loadScriptsFromResources() {
        List<String> scripts = getJavaScriptsListFromResources();
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        for (String script : scripts) {
            try (InputStream is = classLoader.getResourceAsStream(script);
                BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                engine.eval(reader);
            } catch (IOException | ScriptException | NullPointerException e) {
                LOG.error("Loading js error: ", e);
            }
        }
    }

    private String getScriptForKey(String key) {
        return String.format("getKey = function() {" +
                "   return \"%s\"" +
                "}", key);
    }

    private static class SecureParams {
        private final String address;
        private final String secureKey;
        private final Date expiration;

        SecureParams(String address, String secureKey) {
            this.address = address;
            this.secureKey = secureKey;
            this.expiration = new Date(System.currentTimeMillis() + EXPIRATION_KEY_SECONDS * 1000L);
        }

        boolean isExpired() {
            return new Date().after(expiration);
        }

        String getSecureKey() {
            return secureKey;
        }

        String getAddress() {
            return address;
        }
    }
}
