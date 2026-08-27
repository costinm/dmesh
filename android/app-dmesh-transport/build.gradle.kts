plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.github.costinm.dmesh.transport"
    // Android 16 QPR2 (36.1) exposes the public configured LocalOnly Hotspot
    // API used by the optional password regression check. Runtime calls remain
    // guarded so the same APK can run on older devices.
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.github.costinm.dmesh.transport"
        minSdk = providers.gradleProperty("MIN_SDK_VERSION").get().toInt()
        targetSdk = providers.gradleProperty("TARGET_SDK_VERSION").get().toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        versionCode = 1
        versionName = "0.1"
    }

    lint { abortOnError = false }
}

dependencies {
    implementation(project(mapOf("path" to ":android:dmesh-wifi")))
    androidTestImplementation("androidx.test:runner:1.2.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
