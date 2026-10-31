plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.flutterguard.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.flutterguard.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 7
        versionName = "0.3.2"
    }

    signingConfigs {
        create("release") {
            // Kept out of the repository: put these in local.properties or the environment.
            val store = System.getenv("FG_KEYSTORE") ?: "${rootDir}/.keystore/flutterguard.jks"
            val storePassword = System.getenv("FG_KEYSTORE_PASSWORD") ?: "flutterguard"
            val keyAlias = System.getenv("FG_KEY_ALIAS") ?: "flutterguard"
            val keyPassword = System.getenv("FG_KEY_PASSWORD") ?: storePassword
            if (file(store).exists()) {
                storeFile = file(store)
                this.storePassword = storePassword
                this.keyAlias = keyAlias
                this.keyPassword = keyPassword
                // v1/v2 alone still installs, but v3 carries key-rotation proof.
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        debug {
            // Dev-suffixed package: installs side by side with the signed release so the
            // detector changes can be exercised on a real device without touching the
            // release signing identity the shipped APK already has.
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
        }
        release {
            isMinifyEnabled = false
            // Release gate: lint must pass (no errors) on every release build.
            // The remaining warnings are informational: pinned dependency
            // updates, lint's own notion of "latest targetSdk", and the -v26
            // qualifier that aapt2 requires for an adaptive icon.
            lint { checkReleaseBuilds = true; abortOnError = true }
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
