package com.github.costinm.dmeshnative;

public class Rust {

    /**
     *  Load from a specified path - default is relative to the user
     *  dir, which for tests is the gradle project.
     *
     *  The Rust target is one level up - assuming dmesh is part of a
     *  workspace.
     * @param base
     * @return
     */
    public static Rust load(String base) {
        if (base == "") {
            System.load(System.getProperty("user.dir") +
                    "/../../../target/debug/libdmesh.so");
        } else {
            System.load(base + "/libdmesh.so");
        }
        return new Rust();
    }


    /**
     * Load the Rust library using loadLibrary - works on android
     * and if the library is installed in LD_LIBRARY_PATH or default
     * locations.
     */
    public static Rust load() {
        System.loadLibrary("dmesh");
        return new Rust();
    }
    public static native void invokeCallbackViaJNI(Callback c);

    public static class Callback {
        public void callback(String s) {
            System.out.println("Callback received: " + s);
        };
    }

    public static void main(String[] args) {
        invokeCallbackViaJNI(new Callback());
    }
}