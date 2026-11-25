import java.util.Properties

plugins {
    // AGP 9 compiles Kotlin itself (built-in Kotlin): no org.jetbrains.kotlin.android.
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// Release signing key: android-app/keystore.properties + the .jks it names (both git-ignored, never committed).
// Without them a release build is unsigned and only the debug build can be installed.
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
val hasReleaseKey = keystoreProps.getProperty("storeFile")?.let { rootProject.file(it).exists() } == true

android {
    namespace = "ae.saqrintel.shield"
    compileSdk = 36

    defaultConfig {
        applicationId = "ae.saqrintel.shield"
        minSdk = 26
        targetSdk = 36
        versionCode = 2
        versionName = "0.2.0"
    }

    signingConfigs {
        if (hasReleaseKey) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (hasReleaseKey) signingConfig = signingConfigs.getByName("release")
        }
    }

    // Two editions of the same app (same package name, so only one can be installed at a time):
    //  full      = message guard (notification access) + web blocker (accessibility). For phones where the
    //              owner installs it on purpose (adb / developer install) and for the demo.
    //  universal = neither of those services is in the manifest. Google Play Protect blocks sideloaded apps
    //              that declare them, so this is the edition to share as a download. It protects with the
    //              scam-site firewall (local DNS filter), Share -> Saqr and the Scanner.
    flavorDimensions += "edition"
    productFlavors {
        create("full") {
            dimension = "edition"
            buildConfigField("boolean", "FULL_GUARDS", "true")
        }
        create("universal") {
            dimension = "edition"
            versionNameSuffix = "-universal"
            buildConfigField("boolean", "FULL_GUARDS", "false")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    bundle {
        language {
            // In-app EN | AR switch: every locale must ship in the base APK.
            enableSplit = false
        }
    }

    lint {
        warningsAsErrors = false
        abortOnError = true
        checkDependencies = false
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.okhttp)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
}
