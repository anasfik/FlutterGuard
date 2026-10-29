package com.flutterguard.app.ui

import com.flutterguard.app.scan.AppMeta
import com.flutterguard.app.scan.ArtifactCategory
import com.flutterguard.app.scan.ArtifactEntry
import com.flutterguard.app.scan.FrameworkInfo
import com.flutterguard.app.scan.HostInfo
import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.ReportStats
import com.flutterguard.app.scan.SigningInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Long sections preview a bounded subset and say exactly how much is hidden. */
class SectionsTest {

    private fun report(
        deps: List<String> = emptyList(),
        hosts: List<HostInfo> = emptyList(),
    ) = Report(
        meta = AppMeta(
            packageName = "com.a", label = "A", versionName = "1", versionCode = 1,
            minSdk = 26, targetSdk = 35, installer = null, firstInstallMs = 0, lastUpdateMs = 0,
            isSystem = false, sizeBytes = 1, splitCount = 0, abis = emptyList(),
            nativeLibs = emptyList(), baseSha256 = "",
        ),
        framework = FrameworkInfo(isFlutter = true, dartDeps = deps),
        signing = SigningInfo(
            signerSubject = null, signerIssuer = null, sha256Fingerprint = null, debugCert = false,
            multipleSigners = false, rotationHistory = false, validFrom = null, validTo = null, sigAlgorithm = null,
        ),
        findings = emptyList(), hosts = hosts, channels = emptyList(), thirdParty = emptyList(),
        permissions = emptyList(), deepLinks = emptyList(),
        stats = ReportStats(0, 0, 0, 0, 0, 0, 0), grade = 'A',
    )

    @Test
    fun previewCapsAndCounts() {
        val window = preview((1..238).toList())
        assertEquals(PREVIEW_ROWS, window.visible.size)
        assertEquals(238, window.total)
        assertEquals(230, window.hidden)
        assertTrue(window.isCapped)
        assertEquals("Showing 8 of 238 routes", window.countLabel("routes"))
    }

    @Test
    fun shortSectionIsNotCapped() {
        val window = preview(listOf("a", "b", "c"))
        assertEquals(3, window.visible.size)
        assertFalse(window.isCapped)
        assertEquals("3 hosts", window.countLabel("hosts"))
    }

    @Test
    fun emptySectionCountsZero() {
        val window = preview(emptyList<String>())
        assertEquals(emptyList<String>(), window.visible)
        assertEquals("0 findings", window.countLabel("findings"))
    }

    @Test
    fun seeAllRouteIsStillBounded() {
        val page = seeAllPage((1..900).toList())
        assertEquals(SEE_ALL_MAX, page.visible.size)
        assertEquals("Showing 500 of 900 rows", page.countLabel("rows"))
        assertTrue(seeAllPage(listOf(1, 2)).visible.size == 2)
        assertFalse(seeAllPage(listOf(1, 2)).isCapped)
    }

    @Test
    fun seeAllDescribesTheSameFilteredSetAsTheFooter() {
        val deps = (1..300).map { "dep$it" }
        val filtered = filterDependencies(deps, "dep1")
        val window = preview(filtered)
        val rows = SeeAllRows.of(
            SeeAllTarget.DEPENDENCIES,
            report(deps = deps),
            RecoveredPathGroups(),
            artifacts = null,
            secrets = emptyList(),
            deps = filtered,
        )
        assertEquals(111, filtered.size)
        assertEquals(window.total, rows.size)
        assertEquals("Showing 8 of 111 dependencies", window.countLabel("dependencies"))

        val artifacts = (1..40).map {
            ArtifactEntry(0, "base", "assets/file$it.txt", 1, 2, ArtifactCategory.ASSET)
        }
        val kept = artifacts.filter { it.name.contains("file1") }
        val artifactRows = SeeAllRows.of(
            SeeAllTarget.ARTIFACTS,
            report(),
            RecoveredPathGroups(),
            artifacts = kept,
            secrets = emptyList(),
        )
        assertEquals(kept.size, artifactRows.size)
        assertEquals(preview(kept).total, artifactRows.size)
    }

    @Test
    fun unopenableEndpointRowsCarryNoLink() {
        val rows = SeeAllRows.of(
            SeeAllTarget.HOSTS,
            report(
                hosts = listOf(
                    HostInfo("appflowy.io", "app", listOf("https://appflowy.io/doc"), appOwned = true),
                    HostInfo("appflowy.comworkspace", "app", emptyList(), appOwned = true),
                    HostInfo("localhost:11434", "internal", emptyList()),
                ),
            ),
            RecoveredPathGroups(),
            artifacts = null,
            secrets = emptyList(),
        )
        assertEquals("https://appflowy.io/doc", rows.first { it.title.contains("appflowy.io") }.link)
        assertNull(rows.first { it.title.contains("comworkspace") }.link)
        assertNull(rows.first { it.title.contains("localhost") }.link)
        assertNotNull(rows.first { it.title.contains("appflowy.io") }.link)
    }
}
