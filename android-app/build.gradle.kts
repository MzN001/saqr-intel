// Top-level build file.
buildscript {
    dependencies {
        // AGP 9 built-in Kotlin ships with KGP 2.2.10; this raises it so the
        // Compose compiler plugin (same version) matches. See
        // https://developer.android.com/build/releases/agp-9-0-0-release-notes#runtime-dependency-on-kotlin-gradle-plugin
        classpath(libs.kotlin.gradle.plugin)
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}
