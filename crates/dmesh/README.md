# DMesh Android JNI

This crate owns the Java/Android JNI wrapper for the dmesh mesh runtime.
It is copied from `ssh-mesh/crates/dmesh` and trimmed for Android use:

- JNI bindings live in `src/mesh_jni.rs`.
- Shared mesh startup and stream helpers live in `src/mesh_common.rs`.
- Python bindings are intentionally not included here; they remain in the
  `ssh-mesh` repository.

The Android build harness compiles this crate with `cargo ndk` and copies the
resulting `libdmesh.so` into `android/app-dmesh/src/main/jniLibs`.
