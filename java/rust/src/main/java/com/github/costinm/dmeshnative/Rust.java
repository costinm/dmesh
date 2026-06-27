package com.github.costinm.dmeshnative;

import java.io.File;
import java.net.URI;

/**
 * Native library loader for the DMesh JNI bindings.
 */
public class Rust {
    private static boolean loaded = false;

    private static String nativeArch() {
        String arch = System.getProperty("os.arch", "");
        switch (arch) {
            case "amd64":
            case "x86_64":
                return "x86_64";
            case "aarch64":
                return "arm64-v8a";
            case "arm":
                return "armeabi-v7a";
            case "x86":
            case "i386":
            case "i686":
                return "x86";
            default:
                return arch;
        }
    }

    public static synchronized void loadLibrary() {
        if (loaded) {
            return;
        }

        String arch = nativeArch();
        try {
            URI jarUri = Rust.class.getProtectionDomain().getCodeSource().getLocation().toURI();
            File jarFile = new File(jarUri);
            File jarDir = jarFile.isFile() ? jarFile.getParentFile() : jarFile;

            File libFromJar = new File(jarDir, "../lib/" + arch + "/libdmesh.so");
            if (libFromJar.exists()) {
                System.load(libFromJar.getCanonicalPath());
                loaded = true;
                return;
            }

            File libSameDir = new File(jarDir, "libdmesh.so");
            if (libSameDir.exists()) {
                System.load(libSameDir.getCanonicalPath());
                loaded = true;
                return;
            }
        } catch (Exception ignored) {
            // Fall through to the platform loader.
        }

        System.loadLibrary("dmesh");
        loaded = true;
    }

    public static Rust load() {
        loadLibrary();
        return new Rust();
    }
}
