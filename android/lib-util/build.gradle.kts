plugins {
    alias(libs.plugins.android.library)
}

android {
    compileSdkVersion(providers.gradleProperty("COMPILE_SDK_VERSION").get())
    namespace = "com.github.costinm.dmesh.android.util"


    defaultConfig {
        // Utils are compatible with oldest android I can test with.
        minSdk = providers.gradleProperty("MIN_SDK_VERSION_OLD").get().toInt()

        testInstrumentationRunner = "android.support.test.runner.AndroidJUnitRunner"

    }

    testOptions {
        targetSdk = providers.gradleProperty("TARGET_SDK_VERSION").get().toInt()
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    // Only core SDK.
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))
}
