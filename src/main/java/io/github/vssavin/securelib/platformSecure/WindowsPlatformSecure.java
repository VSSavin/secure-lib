package io.github.vssavin.securelib.platformSecure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;

class WindowsPlatformSecure implements PlatformSecure {
    private static final Logger LOG = LoggerFactory.getLogger(WindowsPlatformSecure.class);
    private static final String DEFAULT_KEY = "01234567890";
    private String driveLetter = "C";

    public WindowsPlatformSecure(String driveLetter) {
        this.driveLetter = driveLetter;
    }

    public WindowsPlatformSecure() {
    }

    @Override
    public String getSecureKey() {
        String security = DEFAULT_KEY;
        try {
            String line;
            Process process = Runtime.getRuntime()
                    .exec("cmd /c chcp 65001" + " && cmd /c vol " + driveLetter + ":");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = in.readLine()) != null) {
                if (line.toLowerCase().contains("serial number")) {
                    String[] strings = line.split(" ");
                    security = strings[strings.length - 1];
                }
            }
            in.close();
        } catch (Exception e) {
            LOG.error("Error while getting WindowsSecurity: ", e);
        }
        return security;
    }
}
