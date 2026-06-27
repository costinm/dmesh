plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.github.costinm.dmesh.lm3"
    compileSdkVersion(providers.gradleProperty("COMPILE_SDK_VERSION").get())


    defaultConfig {
        minSdk = providers.gradleProperty("MIN_SDK_VERSION").get().toInt()

        testInstrumentationRunner = "android.support.test.runner.AndroidJUnitRunner"
    }

    testOptions {
        targetSdk = providers.gradleProperty("TARGET_SDK_VERSION").get().toInt()
    }

    lint {
        abortOnError = false
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))
    
    implementation(project(mapOf("path" to ":android:lib-util")))
}
