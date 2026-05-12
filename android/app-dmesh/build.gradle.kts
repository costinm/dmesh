
import com.android.build.api.dsl.ApplicationExtension

plugins {
    alias(libs.plugins.android.application)
}

android {
    signingConfigs {
        create("release") {
            storeFile = file("/home/costin/Private/playstore_lmesh_key_new.jks")
            storePassword = "android"
            keyAlias = "key0"
            keyPassword = "android"
        }
    }
    compileSdkVersion(providers.gradleProperty("COMPILE_SDK_VERSION").get())

    defaultConfig {
        applicationId = "com.github.costinm.dmesh.lm"
        minSdk = providers.gradleProperty("MIN_SDK_VERSION").get().toInt()
        // 30 - Android 11, 2020
        versionCode = 30
        versionName = "1.4"
        multiDexEnabled = false
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    lint {
        targetSdk = providers.gradleProperty("TARGET_SDK_VERSION").get().toInt()
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            //proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            isDebuggable = false
            signingConfig = signingConfigs.getByName("release")
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
    implementation(project(mapOf("path" to ":android:lib-lm3")))
    implementation(project(mapOf("path" to ":android:wpgate-aar")))
    implementation(project(mapOf("path" to ":java:rust")))

    //implementation(libs.androidx.monitor)

    implementation(libs.ext.junit)
}
