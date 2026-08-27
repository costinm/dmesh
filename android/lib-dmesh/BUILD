load("@rules_android//rules:rules.bzl", "android_library")

package(
    default_visibility = ["//src:__subpackages__"],
)

android_library(
    name = "lib-dmesh",
    srcs = [
        "src/main/java/**",
    ],
    manifest = "src/AndroidManifest.xml",
    resource_files = glob(["src/main/res/**"]),
)
