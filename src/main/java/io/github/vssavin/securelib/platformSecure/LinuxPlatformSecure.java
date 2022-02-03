package io.github.vssavin.securelib.platformSecure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;

class LinuxPlatformSecure implements PlatformSecure {
    private static final Logger LOG = LoggerFactory.getLogger(LinuxPlatformSecure.class);
    private static final String DEFAULT_KEY = "01234567890";

    @Override
    public String getSecureKey() {
        String security = DEFAULT_KEY;
        try {
            String line;
            Process process = Runtime.getRuntime()
                    .exec("udevadm info --query=all --name=/dev/sda | grep ID_SERIAL_SHORT");
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(process.getInputStream()) );
            while ((line = in.readLine()) != null) {
                if (line.toUpperCase().contains("ID_SERIAL_SHORT")) {
                    String[] strings = line.split("=");
                    security = strings[1];
                    break;
                }
            }
            in.close();
        }
        catch (Exception e) {
            LOG.error("Error while getting WindowsSecurity: ", e);
        }
        return security;
    }
}
