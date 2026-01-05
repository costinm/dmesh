package com.github.costinm.dmeshnative;

public class Rust {
    static {
        // TODO: pass lib dir explicitly, find
        System.load(System.getProperty("user.dir") + 
        "/../../../target/debug/libdmesh.so");
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