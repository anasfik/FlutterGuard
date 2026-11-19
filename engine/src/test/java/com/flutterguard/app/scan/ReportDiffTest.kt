package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** One report fixture builder shared by the comparison tests in this package. */
internal object DiffFixture {

    fun finding(
        id: String,
        severity: Severity = Severity.MEDIUM,
        kind: FindingKind? = null,
        sources: List<String> = listOf("classes.dex"),
        value: String? = null,
        snippet: String = "matched",
    ): Finding = Finding(
        id = id,
        title = id,
        severity = severity,
        detail = "detail for $id",
        evidence = sources.map { Evidence(source = it, offset = 0, snippet = snippet, value = value) },
        remediation = "fix",
        kind = kind ?: FindingCatalog.kindOf(id, severity),
    )

    fun report(
        packageName: String = "com.example.app",
        versionName: String? = "1.0.0",
        versionCode: Long = 1,
        fileScan: Boolean = false,
        hosts: List<String> = emptyList(),
        permissions: List<String> = emptyList(),
        providers: List<String> = emptyList(),
        deps: List<String> = emptyList(),
        nativeLibs: List<NativeLib> = emptyList(),
        signingSha256: String? = null,
        findings: List<Finding> = emptyList(),
        generatedAt: Long = 1_700_000_000_000,
    ) = Report(
        meta = AppMeta(
            packageName = packageName,
            label = "Example",
            versionName = versionName,
            versionCode = versionCode,
            minSdk = 26,
            targetSdk = 35,
            installer = null,
            firstInstallMs = 0,
            lastUpdateMs = 0,
            isSystem = false,
            sizeBytes = 1024,
            splitCount = 0,
            abis = nativeLibs.map { it.abi }.distinct(),
            nativeLibs = nativeLibs,
            baseSha256 = "",
            fileScan = fileScan,
        ),
        framework = FrameworkInfo(isFlutter = true, dartDeps = deps),
        signing = SigningInfo(
            signerSubject = null,
            signerIssuer = null,
            sha256Fingerprint = signingSha256,
            debugCert = false,
            multipleSigners = false,
            rotationHistory = false,
            validFrom = null,
            validTo = null,
            sigAlgorithm = null,
        ),
        findings = findings,
        hosts = hosts.map { HostInfo(host = it, classification = "app") },
        channels = emptyList(),
        thirdParty = providers.map { ThirdPartyHit(service = it, evidence = emptyList()) },
        permissions = permissions.map { PermissionHit(name = it, protection = "normal", description = "") },
        deepLinks = emptyList(),
        stats = ReportStats(0, 0, 0, 0, 0, stringsScanned = 0, durationMs = 0),
        grade = 'A',
        generatedAt = generatedAt,
    )

    fun lib(name: String, abi: String, sha: String?) = NativeLib(name, abi, 10, sha, emptyList())
}

class ReportDiffTest {

    @Test
    fun additionsAndRemovalsAreSortedAndIndependentOfInputOrder() {
        val before = DiffFixture.report(
            hosts = listOf("b.example", "a.example"),
            permissions = listOf("android.permission.CAMERA", "android.permission.READ_SMS"),
            providers = listOf("Firebase"),
        )
        val after = DiffFixture.report(
            hosts = listOf("c.example", "a.example"),
            permissions = listOf("android.permission.READ_SMS", "android.permission.RECORD_AUDIO"),
            nativeLibs = listOf(DiffFixture.lib("libapp.so", "arm64-v8a", "abc123")),
        )

        val comparison = ReportDiff.compare(before, after)
        assertEquals(ComparisonStatus.COMPARED, comparison.status)
        assertFalse(comparison.rejected)
        assertEquals(
            listOf(
                "PERMISSIONS:ADDED:android.permission.RECORD_AUDIO",
                "PERMISSIONS:REMOVED:android.permission.CAMERA",
                "HOSTS:ADDED:c.example",
                "HOSTS:REMOVED:b.example",
                "PROVIDERS:REMOVED:Firebase",
                "NATIVE_LIBS:ADDED:arm64-v8a/libapp.so",
            ),
            comparison.changes.map { "${it.category}:${it.change}:${it.identity}" },
        )

        // The same evidence, reordered, must produce byte-identical changes.
        val reordered = ReportDiff.compare(
            before.copy(hosts = before.hosts.reversed(), permissions = before.permissions.reversed()),
            after.copy(hosts = after.hosts.reversed(), permissions = after.permissions.reversed()),
        )
        assertEquals(comparison.changes, reordered.changes)
    }

    @Test
    fun versionChangeIsReportedAndASameVersionRescanIsNot() {
        val before = DiffFixture.report()
        val after = DiffFixture.report(versionName = "2.0.0", versionCode = 2)

        val changed = ReportDiff.compare(before, after)
        assertTrue(changed.versionChanged)
        val first = changed.changes.first()
        assertEquals(DiffCategory.VERSION, first.category)
        assertEquals(DiffChange.CHANGED, first.change)
        assertEquals("1.0.0 (1) → 2.0.0 (2)", first.identity)

        // Same version, new artifact evidence: artifact changes, no version claim.
        val rescan = ReportDiff.compare(
            before,
            before.copy(hosts = listOf(HostInfo("new.example", "app")), generatedAt = before.generatedAt + 5_000),
        )
        assertFalse(rescan.versionChanged)
        assertTrue(rescan.changes.none { it.category == DiffCategory.VERSION })
        assertTrue(rescan.changes.any { it.category == DiffCategory.HOSTS && it.change == DiffChange.ADDED })
    }

    @Test
    fun severityAndKindChangesAreReportedOnTheSameIdentity() {
        val before = DiffFixture.report(
            findings = listOf(DiffFixture.finding("SEC-KEY-GENERIC", Severity.MEDIUM, FindingKind.SUSPECTED)),
        )
        val worseSeverity = DiffFixture.report(
            findings = listOf(DiffFixture.finding("SEC-KEY-GENERIC", Severity.HIGH, FindingKind.SUSPECTED)),
        )
        val severityChange = ReportDiff.compare(before, worseSeverity).changes.single()
        assertEquals(DiffChange.CHANGED, severityChange.change)
        assertEquals("SEC-KEY-GENERIC @ classes.dex", severityChange.identity)
        assertEquals("severity MEDIUM → HIGH", severityChange.detail)

        val moreCertain = DiffFixture.report(
            findings = listOf(DiffFixture.finding("SEC-KEY-GENERIC", Severity.MEDIUM, FindingKind.CONFIRMED)),
        )
        val kindChange = ReportDiff.compare(before, moreCertain).changes.single()
        assertEquals(DiffChange.CHANGED, kindChange.change)
        assertEquals("kind SUSPECTED → CONFIRMED", kindChange.detail)
    }

    @Test
    fun theSameRuleFromTwoDistinctSourcesIsReportedSeparately() {
        val after = DiffFixture.report(
            findings = listOf(
                DiffFixture.finding("SEC-KEY-GENERIC", sources = listOf("libapp.so", "classes.dex")),
            ),
        )
        val comparison = ReportDiff.compare(DiffFixture.report(), after)
        assertEquals(
            listOf("SEC-KEY-GENERIC @ classes.dex", "SEC-KEY-GENERIC @ libapp.so"),
            comparison.changes.map { it.identity },
        )
        assertTrue(comparison.changes.all { it.category == DiffCategory.FINDINGS })
        assertTrue(comparison.changes.all { it.change == DiffChange.ADDED })
    }

    @Test
    fun duplicateOccurrencesAreCoalescedExplicitlyAndCounted() {
        val after = DiffFixture.report(
            findings = listOf(
                DiffFixture.finding("SEC-KEY-GENERIC", sources = listOf("classes.dex", "classes.dex", "classes.dex")),
            ),
        )
        val comparison = ReportDiff.compare(DiffFixture.report(), after)
        val change = comparison.changes.single()
        assertEquals(3, change.occurrences)
        assertEquals(2, comparison.coalesced)
    }

    @Test
    fun identicalReportsHaveNoChanges() {
        val report = DiffFixture.report(
            hosts = listOf("a.example"),
            findings = listOf(DiffFixture.finding("SEC-KEY-GENERIC")),
            nativeLibs = listOf(DiffFixture.lib("libapp.so", "arm64-v8a", "abc")),
        )
        val comparison = ReportDiff.compare(report, report.copy(generatedAt = report.generatedAt + 60_000))
        assertEquals(ComparisonStatus.COMPARED, comparison.status)
        assertTrue(comparison.changes.isEmpty())
        assertFalse(comparison.versionChanged)
        assertEquals(0, comparison.coalesced)
    }

    @Test
    fun differentPackagesAreRejectedInsteadOfCompared() {
        val comparison = ReportDiff.compare(
            DiffFixture.report(packageName = "com.alpha.app", hosts = listOf("a.example")),
            DiffFixture.report(packageName = "com.beta.app", hosts = listOf("b.example")),
        )
        assertEquals(ComparisonStatus.PACKAGE_MISMATCH, comparison.status)
        assertTrue(comparison.rejected)
        assertTrue(comparison.changes.isEmpty())
        assertTrue(comparison.unavailable.isEmpty())
        val reason = comparison.rejectedReason.orEmpty()
        assertTrue(reason, reason.contains("com.alpha.app"))
        assertTrue(reason, reason.contains("com.beta.app"))
        assertTrue(reason, reason.contains("package"))
    }

    @Test
    fun installedAndFileNamespacesAreRejectedInsteadOfCompared() {
        val installed = DiffFixture.report(hosts = listOf("a.example"))
        val picked = DiffFixture.report(fileScan = true, hosts = listOf("b.example"))
        val comparison = ReportDiff.compare(installed, picked)
        assertEquals(ComparisonStatus.NAMESPACE_MISMATCH, comparison.status)
        assertTrue(comparison.rejected)
        assertTrue(comparison.changes.isEmpty())
        assertTrue(comparison.rejectedReason.orEmpty().contains("installed"))
    }

    @Test
    fun missingHistoricalCategoriesAreUnavailableNeverRemovals() {
        // A snapshot written before the extended categories existed.
        val legacy = "version:1.0.0 (1)\nhosts:a.example\nroutes:\nfindings:\ndeps:"
        val current = DiffFixture.report(
            versionName = "2.0.0",
            versionCode = 2,
            hosts = listOf("a.example"),
            permissions = listOf("android.permission.CAMERA"),
            providers = listOf("Firebase"),
            nativeLibs = listOf(DiffFixture.lib("libapp.so", "arm64-v8a", "abc")),
            findings = listOf(DiffFixture.finding("NET-CLEARTEXT", Severity.MEDIUM)),
            signingSha256 = "AA:BB",
        )
        val log = ScanLog.append(ScanLog.append(null, legacy), History.snapshot(current))
        val entries = ScanLog.decode(log)
        assertEquals(2, entries.size)

        val comparison = History.comparison(entries, 1, "com.example.app", ScanNamespace.INSTALLED)
        assertNotNull(comparison)
        val unavailable = comparison!!.unavailable
        assertTrue(
            "unavailable was $unavailable",
            unavailable.containsAll(
                listOf(
                    DiffCategory.PERMISSIONS,
                    DiffCategory.PROVIDERS,
                    DiffCategory.NATIVE_LIBS,
                    DiffCategory.NETWORK_POLICY,
                    DiffCategory.SIGNING,
                ),
            ),
        )
        // Unavailable categories are skipped, so nothing "disappeared".
        assertTrue(
            comparison.changes.none {
                it.category in setOf(
                    DiffCategory.PERMISSIONS,
                    DiffCategory.PROVIDERS,
                    DiffCategory.NATIVE_LIBS,
                    DiffCategory.NETWORK_POLICY,
                    DiffCategory.SIGNING,
                )
            },
        )
        assertTrue(comparison.versionChanged)

        val lines = History.diff(entries[0].snapshot, entries[1].snapshot)
        assertTrue(lines.any { it.startsWith("~ version 1.0.0 (1) → 2.0.0 (2)") })
        assertTrue("unexpected native removal in $lines", lines.none { it.startsWith("- native") })
        assertTrue("no explicit unavailable note in $lines", lines.any { it.startsWith("?") && it.contains("native") })
        assertTrue(lines.none { it.startsWith("+ network") || it.startsWith("- network") })
    }

    @Test
    fun oldHistoryLogStaysReadableAndPreviousVersionSkipsRescans() {
        fun snapshot(name: String, code: Long, hosts: List<String>) =
            History.snapshot(DiffFixture.report(versionName = name, versionCode = code, hosts = hosts))

        var log: String? = null
        log = ScanLog.append(log, snapshot("1.0.0", 1, listOf("a.example")))
        log = ScanLog.append(log, snapshot("1.1.0", 2, listOf("a.example", "b.example")))
        log = ScanLog.append(log, snapshot("1.1.0", 2, listOf("a.example", "b.example", "c.example"))) // rescan
        val entries = ScanLog.decode(log)
        assertEquals(3, entries.size)

        // The per-entry log diff must reach the genuinely previous *version*,
        // not the same-version rescan one row earlier.
        val perVersion = ScanLog.diffForPreviousVersion(entries, 2)
        assertTrue(perVersion.toString(), perVersion.any { it.startsWith("~ version 1.0.0 (1) → 1.1.0 (2)") })
        assertTrue(perVersion.toString(), perVersion.contains("+ host b.example"))
        assertTrue(perVersion.toString(), perVersion.contains("+ host c.example"))

        // The newest-vs-previous-scan diff stays available for the inline card.
        val perScan = ScanLog.diffForPreviousScan(entries, 2)
        assertTrue(perScan.toString(), perScan.none { it.startsWith("~ version") })
        assertTrue(perScan.toString(), perScan.contains("+ host c.example"))

        // A legacy hand-written log (no extended categories) still decodes and diffs.
        val legacyLog = "version:0.9.0 (9)\nhosts:a.example\nroutes:\nfindings:LOW|F1\ndeps:dio"
        val legacyEntries = ScanLog.decode(legacyLog)
        assertEquals(1, legacyEntries.size)
        assertEquals("0.9.0", legacyEntries.first().versionName)
        assertTrue(History.diff(legacyLog, legacyLog).single().startsWith("no change"))
    }
}
