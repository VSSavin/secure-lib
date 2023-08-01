package io.github.vssavin.securelib.platformSecure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.*;

class DefaultPlatformSecure implements PlatformSecure {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultPlatformSecure.class);
    private static final boolean DEBUG_ENABLED = LOG.isDebugEnabled();

    private static final List<String> IGNORED_INTERFACES = new ArrayList<>();

    static {
        try {
            ResourceBundle bundle = ResourceBundle.getBundle("defaultPlatformSecure.conf");
            String ignoredString = bundle.getString("ignoredInterfaces");
            String[] splitted = ignoredString.split(",");
            if (splitted.length > 0) {
                for (String str : splitted) {
                    IGNORED_INTERFACES.add(str.trim());
                }
            }

        } catch (MissingResourceException e) {
            if (DEBUG_ENABLED) {
                LOG.debug("Missing ignoredInterfaces resource!");
            }
        }
    }

    @Override
    public String getSecureKey() {
        String key = "";
        try {
            Set<String> ids = getNetworkIds();
            if (!ids.isEmpty()) {
                StringBuilder all = new StringBuilder();
                for (String str: ids) {
                    all.append(str);
                }
                key = all.toString().replace("\u0000", "");
            } else {
                key = "01234567890";
            }
        } catch (Exception ex) {
            LOG.error("Error while getting HARDWARE ADDRESSES: ", ex);
        }

        return key;
    }

    private Set<String> getNetworkIds() throws SocketException {
        Enumeration<NetworkInterface> net = NetworkInterface.getNetworkInterfaces();
        Set<String> ids = new TreeSet<>();

        while (net.hasMoreElements()) {
            NetworkInterface element = net.nextElement();
            if (!isIgnoredInterface(element.getName())) {
                String macAddress = getMacAddress(element);
                if (!macAddress.isEmpty()) {
                    ids.add(macAddress);
                }
            }
        }

        return ids;
    }

    private String getMacAddress(NetworkInterface networkInterface) throws SocketException {
        byte[] mac = networkInterface.getHardwareAddress();
        StringBuilder sb = new StringBuilder();
        if (mac != null) {
            for (int i = 0; i < mac.length; i++) {
                sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
            }
        }
        return sb.toString();
    }

    private boolean isIgnoredInterface(String name) {
        boolean ignored = false;
        for (String ignoredInterface : IGNORED_INTERFACES) {
            if (name.contains(ignoredInterface)) {
                ignored = true;
                break;
            }
        }

        return ignored;
    }
}
