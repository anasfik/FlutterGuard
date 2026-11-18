plugins {
    id("org.jetbrains.kotlin.jvm")
    application
}

// Bytecode targets JDK 17 without a toolchain lookup: this cache has no JDK 17
// installation, and a toolchain request would need a network download.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

application {
    mainClass.set("com.flutterguard.cli.MainKt")
    // Launcher and distribution are named `flutterguard`; the docs and the
    // benchmark harness both invoke that name.
    applicationName = "flutterguard"
}

dependencies {
    implementation(project(":engine"))
    // The engine has org.json on compileOnly (the Android platform supplies it).
    // A plain JDK has no org.json, so the CLI must ship it.
    implementation("org.json:json:20240303")
    // Declared explicitly: the engine's own coroutine dependency is an
    // `implementation` edge and is therefore not on this module's compile classpath.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    testImplementation("junit:junit:4.13.2")
}
