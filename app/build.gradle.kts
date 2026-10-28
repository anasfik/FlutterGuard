plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.flutterguard.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.flutterguard.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "0.1.1"
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
        release {
            isMinifyEnabled = false
            // lintVital needs the lint-gradle artifact; skip it for offline release builds.
            lint { checkReleaseBuilds = false }
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
