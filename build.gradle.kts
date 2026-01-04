// Top-level build file where you can add configuration options common to all sub-projects/modules.
// Kotlin (and others) appears to require the plugin to be defined only
// once, and that's why this file is needed.

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
    id("com.google.gms.google-services") version "4.4.4" apply false
}
