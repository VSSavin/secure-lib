package io.github.vssavin.securelib;

import java.lang.reflect.Field;
import java.util.Arrays;

/**
 * Created by vssavin on 01.08.2022.
 */
public final class Utils {

    private Utils() {

    }

    public static void clearString(String string) {
        try {
            Field stringChars = String.class.getDeclaredField("value");
            try {
                stringChars.setAccessible(true);
            } catch (Exception inaccessible) {
                String errorMessage = "setAccessible on string chars may throw an InaccessibleObjectException\n" +
                        "for some versions of JVM. To solve this problem add vm option:\n" +
                        "--add-opens java.base/java.lang=ALL-UNNAMED";
                System.err.println(errorMessage);
                throw new RuntimeException(errorMessage, inaccessible);
            }

            try {
                char[] chars = (char[]) stringChars.get(string);
                Arrays.fill(chars, '*');
            } catch (ClassCastException castException) {
                byte[] bytes = (byte[]) stringChars.get(string);
                Arrays.fill(bytes, (byte) '*');
            }

        } catch (Exception e) {
            throw new RuntimeException("String clearing error!", e);
        }
    }
}
