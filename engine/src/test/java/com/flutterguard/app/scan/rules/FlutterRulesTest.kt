package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.FindingKind
import com.flutterguard.app.scan.SnapshotKind
import com.flutterguard.app.scan.SnapshotMetadata
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** FLUT-JIT-SNAPSHOT may only fire when the artifact really carries no AOT library. */
class FlutterRulesTest {

    private fun ids(
        zipNames: Set<String>,
        appSoExists: Boolean,
        kernelBlobBytes: Long? = null,
        snapshotBytes: Long? = null,
    ) = FlutterRules.evaluate(
        zipNames = zipNames,
        engineVersionString = null,
        appSoExists = appSoExists,
        packageUriCount = 0,
        camelCount = 0,
        libappSha256 = null,
        kernelBlobBytes = kernelBlobBytes,
        snapshotBytes = snapshotBytes,
        kernelFiles = emptyList(),
    ).second.map { it.id }.toSet()

    @Test
    fun snapshotWithoutAotLibraryIsReported() {
        val found = ids(
            zipNames = setOf("assets/flutter_assets/isolate_snapshot_data", "lib/arm64-v8a/libflutter.so"),
            appSoExists = false,
            snapshotBytes = 4L * 1024 * 1024,
        )
        assertTrue("expected FLUT-JIT-SNAPSHOT", "FLUT-JIT-SNAPSHOT" in found)
    }

    @Test
    fun snapshotBesideAnAotLibraryIsNotReportedAsMissing() {
        val found = ids(
            zipNames = setOf(
                "assets/flutter_assets/isolate_snapshot_data",
                "lib/arm64-v8a/libapp.so",
                "lib/arm64-v8a/libflutter.so",
            ),
            appSoExists = true,
            snapshotBytes = 4L * 1024 * 1024,
        )
        assertFalse("libapp.so is present, so nothing is missing", "FLUT-JIT-SNAPSHOT" in found)
    }

    private fun findings(snapshot: SnapshotMetadata? = null): List<Finding> = FlutterRules.evaluate(
        zipNames = setOf("lib/arm64-v8a/libapp.so", "lib/arm64-v8a/libflutter.so"),
        engineVersionString = null,
        appSoExists = true,
        // Enough names that the heuristic reports; below that it stays quiet.
        packageUriCount = 5,
        camelCount = 40,
        libappSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        kernelBlobBytes = null,
        snapshotBytes = null,
        kernelFiles = emptyList(),
        snapshot = snapshot,
    ).second

    private fun snapshot(kind: SnapshotKind) = SnapshotMetadata(
        symbol = "_kDartIsolateSnapshotData",
        fileOffset = 17856,
        storedLength = 1232199,
        kind = kind,
        serializationHash = "ace654289f5abc240509fc941453ebc5",
        features = listOf("product/arm64/android/compressed-pointers"),
    )

    @Test
    fun symbolCountsAreAHeuristicNotAnObfuscationVerdict() {
        val f = findings().first { it.id == "FLUT-NO-OBFUSCATION" }
        assertFalse("title must not assert obfuscation", f.title.contains("not obfuscated", ignoreCase = true))
        assertFalse("detail must not assert obfuscation", f.detail.contains("not obfuscated", ignoreCase = true))
        assertTrue("counts must be labelled as a heuristic", f.detail.contains("heuristic", ignoreCase = true))
        assertEquals("heuristic counts stay a lead", FindingKind.SUSPECTED, f.kind)
    }

    @Test
    fun libappHashIsAnArtifactFingerprintNotAnEngineIdentifier() {
        val f = findings().first { it.id == "FLUT-FINGERPRINT" }
        assertTrue("must say what the hash does not identify", f.detail.contains("not the Flutter engine", ignoreCase = true))
        assertTrue("must name the artifact", f.detail.contains("libapp.so"))
        assertFalse("must not call the hash an engine build", f.detail.contains("engine build", ignoreCase = true))
    }

    @Test
    fun fullAotSnapshotMetadataIsSurfaced() {
        val info = FlutterRules.evaluate(
            zipNames = setOf("lib/arm64-v8a/libapp.so"),
            engineVersionString = null,
            appSoExists = true,
            packageUriCount = 3,
            camelCount = 40,
            libappSha256 = null,
            kernelBlobBytes = null,
            snapshotBytes = null,
            kernelFiles = emptyList(),
            snapshot = snapshot(SnapshotKind.FULL_AOT),
        ).first
        assertEquals("full-AOT", info.snapshotKind)
        assertEquals("ace654289f5abc240509fc941453ebc5", info.snapshotHash)
        assertEquals(listOf("product/arm64/android/compressed-pointers"), info.snapshotFeatures)
    }

    @Test
    fun nonAotSnapshotMetadataStaysUnknown() {
        val info = FlutterRules.evaluate(
            zipNames = setOf("lib/arm64-v8a/libapp.so"),
            engineVersionString = null,
            appSoExists = true,
            packageUriCount = 3,
            camelCount = 40,
            libappSha256 = null,
            kernelBlobBytes = null,
            snapshotBytes = null,
            kernelFiles = emptyList(),
            snapshot = snapshot(SnapshotKind.FULL_JIT),
        ).first
        assertNull("a JIT header is not AOT evidence", info.snapshotKind)
        assertNull(info.snapshotHash)
        assertTrue(info.snapshotFeatures.isEmpty())
    }

    @Test
    fun jitKernelTakesPrecedenceOverSnapshotWording() {
        val found = ids(
            zipNames = setOf("assets/flutter_assets/kernel_blob.bin"),
            appSoExists = false,
            kernelBlobBytes = 8L * 1024 * 1024,
            snapshotBytes = 4L * 1024 * 1024,
        )
        assertTrue("expected FLUT-DEBUG-BUILD", "FLUT-DEBUG-BUILD" in found)
        assertFalse("debug kernel is its own finding", "FLUT-JIT-SNAPSHOT" in found)
    }
}
