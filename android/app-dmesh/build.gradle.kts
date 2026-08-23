
plugins {
    alias(libs.plugins.android.application)
}

android {
    fun stringPropertyOrEnv(name: String, defaultValue: String): String {
        return providers.gradleProperty(name)
            .orElse(providers.environmentVariable(name))
            .orElse(defaultValue)
            .get()
    }

    val releaseKeystore = file(stringPropertyOrEnv(
        "DMESH_RELEASE_STORE_FILE",
        "${System.getProperty("user.home")}/.ssh/secrets/android/release.jks"
    ))
    val releaseStorePassword = stringPropertyOrEnv("DMESH_RELEASE_STORE_PASSWORD", "android")
    val releaseKeyAlias = stringPropertyOrEnv("DMESH_RELEASE_KEY_ALIAS", "key0")
    val releaseKeyPassword = stringPropertyOrEnv("DMESH_RELEASE_KEY_PASSWORD", "android")

    signingConfigs {
        if (releaseKeystore.exists()) {
            create("release") {
                storeFile = releaseKeystore
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }
    // Android 16 QPR2 (36.1) exposes the public LocalOnly Hotspot WPA2 and
    // SSID setters. The app still targets 36 and retains the API 26 legacy
    // hotspot fallback for older devices.
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.github.costinm.dmesh.lm"
        minSdk = providers.gradleProperty("MIN_SDK_VERSION").get().toInt()
        targetSdk = providers.gradleProperty("TARGET_SDK_VERSION").get().toInt()
        // 30 - Android 11, 2020
        versionCode = 30
        versionName = "1.4"
        multiDexEnabled = false
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            //proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            isDebuggable = false
            signingConfig = if (releaseKeystore.exists()) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    lint {
        abortOnError = false
    }
    namespace = "com.github.costinm.dmesh.lm"
}

//play {
//    serviceAccountCredentials = file("/home/costin/Private/playstore.json")
//    // internal alpha beta production
//    track = "production"
//    userFraction = 1
//}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))
    androidTestImplementation("androidx.test:runner:1.2.0")

    //implementation(libs.androidx.appcompat)
    //implementation(libs.androidx.cardview)
    //implementation(libs.androidx.constraintlayout)
    //implementation(libs.material)

    //implementation("androidx.tracing:tracing:1.3.0")
    //implementation("androidx.core:core:1.17.0")

    implementation(project(mapOf("path" to ":android:lib-util")))

    //implementation(libs.androidx.monitor)

    implementation(libs.ext.junit)
}
