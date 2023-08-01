package io.github.vssavin.securelib.platformSecure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class PlatformSecureFactory {
    private static final Logger LOG = LoggerFactory.getLogger(PlatformSecureFactory.class);
    private static final String WINDOWS_DRIVE_LETTER = "C";

    public static PlatformSecure getPlatformSecurity() {
        PlatformSecure platformSecurity;
        String usePlatformProperty = System.getProperty("security.usePlatform");
        if (usePlatformProperty != null) {
            platformSecurity = getPlatformSecurity(usePlatformProperty);
        } else {
            String systemName = System.getProperty("os.name").toLowerCase();
            if (systemName.contains("lin")) {
                platformSecurity = new LinuxPlatformSecure();
            } else if (systemName.contains("win")) {
                platformSecurity = new WindowsPlatformSecure(WINDOWS_DRIVE_LETTER);
            } else {
                platformSecurity = new DefaultPlatformSecure();
            }
        }

        if (!(platformSecurity instanceof DefaultPlatformSecure)) {
            if (platformSecurity.getSecureKey().isEmpty()) {
                platformSecurity = new DefaultPlatformSecure();
            }
        }

        return platformSecurity;
    }

    private static PlatformSecure getPlatformSecurity(String name) {
        try {
            List<Class> classes = getClasses();
            for (Class clazz : classes) {
                if (clazz.getSimpleName().toLowerCase().contains(name)) {
                    try {
                        Constructor constructor = clazz.getDeclaredConstructor();
                        return (PlatformSecure) constructor.newInstance();
                    } catch (NoSuchMethodException | IllegalAccessException |
                            InstantiationException | InvocationTargetException e) {
                        LOG.error(String.format("Creating new instance of class %s error!", clazz.getSimpleName()), e);
                    }
                }
            }
        } catch (ClassNotFoundException | IOException e) {
            LOG.error("Platform security definition error!", e);
        }

        return new DefaultPlatformSecure();
    }

    private static List<Class> getClasses()
            throws ClassNotFoundException, IOException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        assert classLoader != null;
        String packageName = PlatformSecureFactory.class.getPackage().getName();
        String path = packageName.replace('.', '/');
        Enumeration<URL> resources = classLoader.getResources(path);
        List<File> dirs = new ArrayList<>();
        while (resources.hasMoreElements()) {
            URL resource = resources.nextElement();
            dirs.add(new File(resource.getFile()));
        }
        ArrayList<Class> classes = new ArrayList<>();
        for (File directory : dirs) {
            classes.addAll(findClasses(directory, packageName));
        }
        return classes;
    }

    private static List<Class> findClasses(File directory, String packageName) throws ClassNotFoundException {
        List<Class> classes = new ArrayList<>();
        if (!directory.exists()) {
            return classes;
        }
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    assert !file.getName().contains(".");
                    classes.addAll(findClasses(file, packageName + "." + file.getName()));
                } else if (file.getName().endsWith(".class")) {
                    classes.add(Class.forName(packageName + '.' + file.getName().substring(0, file.getName().length() - 6)));
                }
            }
        }

        return classes;
    }
}
