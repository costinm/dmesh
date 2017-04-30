android_binary(
    name = "lmesh",
    srcs = glob(["src/main/java/**/*.java"]),
    custom_package = "com.github.costinm.dmesh.lm",
    manifest = "src/main/AndroidManifest.xml",
    resource_files = glob(["src/main/res/**"]),
    deps = [
        "//external:support-annotations",
        "//lib-lm",
    ],
)
