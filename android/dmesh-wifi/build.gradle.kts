plugins {
    alias(libs.plugins.android.library)
}

android {
    // Keep the library at the same public-API level as both current callers.
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }
    namespace = "com.github.costinm.dmesh.wifi"

    defaultConfig {
        minSdk = providers.gradleProperty("MIN_SDK_VERSION").get().toInt()
    }

    lint { abortOnError = false }
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))
    implementation(project(mapOf("path" to ":android:lib-dmesh")))
}
