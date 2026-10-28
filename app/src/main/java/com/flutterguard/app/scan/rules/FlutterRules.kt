package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.FrameworkInfo
import com.flutterguard.app.scan.Severity

/** Flutter evidence: engine, build mode, obfuscation, other-framework detection. */
object FlutterRules {

    private val dartVmVersion = Regex("""(?:Dart VM version:\s*)?(\d+\.\d+\.\d+) \((?:stable|beta|dev)\)""")

    /** Libraries that only the debug/JIT engine build ships. */
    private const val VALIDATION_LAYER = "libVkLayer_khronos_validation.so"

    fun evaluate(
        zipNames: Set<String>,
        engineVersionString: String?,
        appSoExists: Boolean,
        packageUriCount: Int,
        camelCount: Long,
        libappSha256: String?,
        kernelBlobBytes: Long?,
        snapshotBytes: Long?,
        kernelFiles: List<String>,
    ): Pair<FrameworkInfo, List<Finding>> {
        val findings = ArrayList<Finding>()
        val hasFlutterAssets = zipNames.any { it.startsWith("assets/flutter_assets/") }
        val libNames = zipNames.filter { it.startsWith("lib/") && it.endsWith(".so") }
        val abis = zipNames.mapNotNull { if (it.startsWith("lib/")) it.split("/").getOrNull(1) else null }.toSortedSet()
        val libBaseNames = libNames.map { it.substringAfterLast('/') }.toSet()

        val dartVersion = engineVersionString?.let { dartVmVersion.find(it)?.groupValues?.get(1) }
        val debugJit = kernelBlobBytes != null
        val hasLibapp = appSoExists || libBaseNames.contains("libapp.so")
        val engineDebug = libBaseNames.contains(VALIDATION_LAYER) || debugJit
        val isFlutter = hasLibapp || libBaseNames.contains("libflutter.so") || hasFlutterAssets

        val buildMode = when {
            debugJit -> "debug (JIT kernel)"
            hasLibapp -> "release (AOT)"
            hasFlutterAssets -> "profile/jit (no AOT snapshot)"
            else -> null
        }

        if (debugJit) {
            val mb = (kernelBlobBytes ?: 0L) / 1024 / 1024
            val sample = if (kernelFiles.isEmpty()) "" else
                " Recoverable library paths include: " + kernelFiles.take(6).joinToString() +
                    (if (kernelFiles.size > 6) " …" else "") + "."
            findings += Finding(
                id = "FLUT-DEBUG-BUILD",
                title = "Flutter debug build shipped — Dart code is near-source",
                severity = Severity.HIGH,
                detail = "assets/flutter_assets/kernel_blob.bin (${mb} MB) is a Dart JIT kernel: package URIs, class/method " +
                    "names, string literals and business logic are recoverable without any disassembly.$sample " +
                    "Production artifacts must ship an AOT libapp.so instead.",
                evidence = kernelFiles.take(3).map { com.flutterguard.app.scan.Evidence("assets/flutter_assets/kernel_blob.bin", 0, it) },
                remediation = "Build with `flutter build appbundle --release`; never distribute debug/`flutter run` artifacts.",
                masvs = listOf("MASVS-RESILIENCE-1", "MASVS-CODE-1"),
            )
        }

        if (!debugJit && (snapshotBytes ?: 0L) > 0) findings += Finding(
            id = "FLUT-JIT-SNAPSHOT",
            title = "JIT snapshot data bundled without AOT library",
            severity = Severity.MEDIUM,
            detail = "isolate_snapshot_data/vm_snapshot_data are present (${(snapshotBytes ?: 0L) / 1024 / 1024} MB) but no libapp.so was found. " +
                "This is a profile/JIT-style artifact; the Dart isolate can be reproduced with `flutter attach` on desktop.",
            evidence = emptyList(),
            remediation = "Ship release AOT builds only.",
            masvs = listOf("MASVS-RESILIENCE-1"),
        )

        if (isFlutter && engineDebug && !debugJit) findings += Finding(
            id = "FLUT-DEBUG-ENGINE",
            title = "Debug Flutter engine libraries bundled",
            severity = Severity.MEDIUM,
            detail = "The APK contains $VALIDATION_LAYER, which only ships with the debug engine. Debug engines keep assertions, " +
                "service extensions and the Dart VM service reachable.",
            evidence = emptyList(),
            remediation = "Rebuild against the release engine (flutter build --release).",
            masvs = listOf("MASVS-RESILIENCE-1"),
        )

        if (isFlutter && !hasLibapp && !debugJit && hasFlutterAssets) findings += Finding(
            id = "FLUT-NO-AOT",
            title = "No AOT Dart snapshot in the artifact",
            severity = Severity.MEDIUM,
            detail = "flutter_assets are present but libapp.so is missing and no kernel blob was found: the Dart code must be " +
                "loaded from another split or the artifact is incomplete.",
            evidence = emptyList(),
            remediation = "Verify the release build produces lib/<abi>/libapp.so.",
            masvs = listOf("MASVS-RESILIENCE-1"),
        )

        if (isFlutter && !abis.contains("arm64-v8a")) findings += Finding(
            id = "FLUT-NO-ARM64",
            title = "No arm64-v8a Flutter engine",
            severity = Severity.INFO,
            detail = "ABIs present: ${abis.joinToString().ifEmpty { "none" }}. 64-bit-only devices and Play's 64-bit " +
                "requirement need arm64-v8a.",
            evidence = emptyList(),
            remediation = "Build a fat AAB so the store splits per-ABI.",
        )

        val obfuscated = if (isFlutter && hasLibapp) packageUriCount < 3 || camelCount < 20 else null
        if (obfuscated == false) findings += Finding(
            id = "FLUT-NO-OBFUSCATION",
            title = "Dart symbols not obfuscated",
            severity = Severity.LOW,
            detail = "libapp.so contains $packageUriCount package: URIs and $camelCount CamelCase identifiers — class/library " +
                "structure can be recovered with tools like Blutter.",
            evidence = emptyList(),
            remediation = "Build with --obfuscate --split-debug-info and keep the symbols file private.",
            masvs = listOf("MASVS-RESILIENCE-2"),
        )

        val others = ArrayList<String>()
        if (libBaseNames.contains("libhermes.so") || zipNames.any { it.endsWith("index.android.bundle") }) others.add("React Native")
        if (zipNames.any { it.startsWith("assets/www/") }) others.add("Cordova/Capacitor")
        if (libBaseNames.contains("libunity.so") || libBaseNames.contains("libil2cpp.so")) others.add("Unity")

        val info = FrameworkInfo(
            isFlutter = isFlutter,
            engineVersion = engineVersionString?.take(120),
            dartVersion = dartVersion,
            obfuscated = obfuscated,
            buildMode = buildMode,
            otherFrameworks = others,
            kernelBlobBytes = kernelBlobBytes,
            snapshotBytes = snapshotBytes,
            engineDebug = engineDebug,
            libappMissing = !hasLibapp,
        )
        if (hasLibapp && libappSha256 != null) findings += Finding(
            id = "FLUT-FINGERPRINT",
            title = "libapp.so fingerprint",
            severity = Severity.INFO,
            detail = "SHA-256 of the Dart AOT snapshot: $libappSha256. Match this against reFlutter's enginehash.csv / Blutter for desktop follow-up.",
            evidence = emptyList(),
            remediation = "Use the hash to identify the exact engine build when doing desktop analysis.",
        )
        return info to findings
    }
}
