plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.github.costinm.dmesh.chat"
    compileSdkVersion(providers.gradleProperty("COMPILE_SDK_VERSION").get())

    defaultConfig {
        applicationId = "com.github.costinm.dmesh.chat"
        minSdk = providers.gradleProperty("MIN_SDK_VERSION").get().toInt()
        versionCode = 1
        versionName = "0.1"
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
        }
    }

    lint {
        abortOnError = false
    }
}

dependencies {
    implementation(project(mapOf("path" to ":android:lib-util")))
}
