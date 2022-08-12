package io.github.vssavin.securelib;

import org.junit.Assert;
import org.junit.Test;

/**
 * Created by vssavin on 12.08.2022.
 */
public class UtilsTest {

    @Test
    public void clearStringTest() {
        String testString1 = "test";
        @SuppressWarnings("StringBufferReplaceableByString")
        String testString2 = new StringBuilder().append(testString1).toString();
        Utils.clearString(testString1);
        Assert.assertNotEquals(testString1, testString2);
    }
}
