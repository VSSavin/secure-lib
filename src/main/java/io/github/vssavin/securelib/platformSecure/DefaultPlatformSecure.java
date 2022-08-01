package io.github.vssavin.securelib.platformSecure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.NetworkInterface;
import java.util.*;

class DefaultPlatformSecure implements PlatformSecure {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultPlatformSecure.class);
    private static final boolean debug = LOG.isDebugEnabled();

    private static final List<String> IGNORED_INTERFACES = new ArrayList<>();

    static {
        try {
            ResourceBundle bundle = ResourceBundle.getBundle("defaultPlatformSecure.conf");
            String ignoredString = bundle.getString("ignoredInterfaces");
            String[] splitted = ignoredString.split(",");
            if (splitted.length > 0) {
                for(String str : splitted) {
                    IGNORED_INTERFACES.add(str.trim());
                }
            }

        } catch (MissingResourceException e) {
            if (debug) {
                LOG.debug("Missing ignoredInterfaces resource!");
            }
        }
    }

    @Override
    public String getSecureKey() {
        String key = "";
        try {
            Enumeration<NetworkInterface> net = NetworkInterface.getNetworkInterfaces();
            Set<String> ids = new TreeSet<>();

            while(net.hasMoreElements()) {
                NetworkInterface element = net.nextElement();

                if (!isIgnoredInterface(element.getName())) {
                    byte[] mac = element.getHardwareAddress();
                    StringBuilder sb = new StringBuilder();
                    if (mac != null) {
                        for (int i = 0; i < mac.length; i++) {
                            sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                        }
                    }
                    String macAddress = sb.toString();
                    if (!macAddress.isEmpty())  ids.add(sb.toString());
                }
            }

            if (ids.size() > 0) {
                StringBuilder all = new StringBuilder();
                for (String str: ids) {
                    all.append(str);
                }
                key = all.toString().replaceAll("\u0000", "");
            }
            else {
                key = "01234567890";
            }
        }
        catch (Exception ex) {
            LOG.error("Error while getting HARDWARE ADDRESSES: ", ex);
        }

        return key;
    }

    private boolean isIgnoredInterface(String name) {
        boolean ignored = false;
        for(String ignoredInterface : IGNORED_INTERFACES) {
            if (name.contains(ignoredInterface)) {
                ignored = true;
                break;
            }
        }

        return ignored;
    }
}
