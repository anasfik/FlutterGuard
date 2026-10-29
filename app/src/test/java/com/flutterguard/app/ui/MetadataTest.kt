package com.flutterguard.app.ui

import com.flutterguard.app.scan.AppMeta
import com.flutterguard.app.scan.FrameworkInfo
import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.ReportStats
import com.flutterguard.app.scan.SigningInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Decompile/check metadata is derived from the stored report; missing values say so. */
class MetadataTest {

    private fun report(
        framework: FrameworkInfo,
        strings: Long = 12_345,
        durationMs: Long = 4_500,
        splitCount: Int = 1,
    ) = Report(
        meta = AppMeta(
            packageName = "com.example.app", label = "Example", versionName = "1.2.3", versionCode = 7,
            minSdk = 26, targetSdk = 35, installer = "com.android.vending",
            firstInstallMs = 0, lastUpdateMs = 0, isSystem = false,
            sizeBytes = 4_000_000, splitCount = splitCount, abis = listOf("arm64-v8a"),
            nativeLibs = emptyList(), baseSha256 = "abc",
        ),
        framework = framework,
        signing = SigningInfo(
            signerSubject = null, signerIssuer = null, sha256Fingerprint = null, debugCert = false,
            multipleSigners = false, rotationHistory = false, validFrom = null, validTo = null, sigAlgorithm = null,
        ),
        findings = emptyList(), hosts = emptyList(), channels = emptyList(), thirdParty = emptyList(),
        permissions = emptyList(), deepLinks = emptyList(),
        stats = ReportStats(0, 0, 0, 0, 0, stringsScanned = strings, durationMs = durationMs),
        grade = 'A', generatedAt = 1_700_000_000_000,
    )

    private fun value(rows: List<MetadataRow>, label: String): String =
        rows.first { it.label == label }.value

    @Test
    fun realRecoveredValuesAreShown() {
        val rows = ReportMetadata.rows(
            report(
                FrameworkInfo(
                    isFlutter = true, engineVersion = "3.24.1 (stable)", dartVersion = "3.5.0",
                    buildMode = "release (AOT)", obfuscated = false,
                ),
            ),
        )
        assertEquals("3.24.1 (stable)", value(rows, "Flutter engine"))
        assertEquals("3.5.0", value(rows, "Dart runtime"))
        assertEquals("release (AOT)", value(rows, "Build mode"))
        assertEquals("2 parts (1 split)", value(rows, "APK parts"))
        assertEquals("4,500 ms", value(rows, "Scan time"))
    }

    @Test
    fun missingValuesSayNotAvailableInsteadOfInventing() {
        val rows = ReportMetadata.rows(report(FrameworkInfo(isFlutter = true)))
        assertEquals("not available", value(rows, "Flutter engine"))
        assertEquals("not available", value(rows, "Dart runtime"))
        assertEquals("not available", value(rows, "Build mode"))
        assertEquals("not available", value(rows, "Obfuscated"))
    }

    @Test
    fun flutterCheckExplainsWhyDeepAnalysisRan() {
        val kernel = ReportMetadata.rows(report(FrameworkInfo(isFlutter = true, kernelBlobBytes = 2_000_000)))
        assertTrue(value(kernel, "Flutter check").contains("kernel_blob.bin"))

        val aot = ReportMetadata.rows(report(FrameworkInfo(isFlutter = true, buildMode = "release (AOT)")))
        assertTrue(value(aot, "Flutter check").contains("libapp.so"))

        val notFlutter = ReportMetadata.rows(
            report(FrameworkInfo(isFlutter = false, otherFrameworks = listOf("React Native"))),
        )
        assertEquals("not a Flutter app (React Native)", value(notFlutter, "Flutter check"))
    }

    @Test
    fun stringsAndTimingComeFromTheScanPath() {
        val rows = ReportMetadata.rows(report(FrameworkInfo(isFlutter = true), strings = 987_654, durationMs = 61_000))
        assertEquals("987,654", value(rows, "Strings scanned"))
        assertEquals("61,000 ms", value(rows, "Scan time"))
    }

    @Test
    fun unmeasuredTimingAndMissingTimestampAreNotInvented() {
        val rows = ReportMetadata.rows(
            report(FrameworkInfo(isFlutter = true), strings = 0, durationMs = 0).copy(generatedAt = 0),
        )
        assertEquals("not available", value(rows, "Scan time"))
        assertEquals("not available", value(rows, "Scanned at"))
    }
}
