package io.github.vssavin.securelib;

import java.lang.reflect.Field;
import java.util.Arrays;

/**
 * Created by vssavin on 01.08.2022.
 */
public class Utils {
    public static void clearString(String string) {
        try {
            Field stringChars = String.class.getDeclaredField("value");
            stringChars.setAccessible(true);
            char[] chars = (char[]) stringChars.get(string);
            Arrays.fill(chars, '*');
        } catch (Exception e) {
            throw new RuntimeException("String clearing error!", e);
        }
    }
}
