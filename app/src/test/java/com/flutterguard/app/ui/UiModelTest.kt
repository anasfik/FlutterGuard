package com.flutterguard.app.ui

import com.flutterguard.app.scan.InstalledApp
import com.flutterguard.app.scan.ReportExport
import com.flutterguard.app.scan.ReportSection
import com.flutterguard.app.scan.RouteNode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure UI logic: inventory filtering, identifier/link validation, formatting. */
class UiModelTest {

    private fun app(pkg: String, label: String, flutter: Boolean, system: Boolean = false) =
        InstalledApp(
            packageName = pkg, label = label, versionName = "1.0", versionCode = 1,
            minSdk = 26, targetSdk = 35, isFlutter = flutter, isSystem = system,
            sizeBytes = 1024, splitCount = 0, icon = null,
        )

    @Test
    fun inventoryFilterHonoursQueryFlutterAndSystemFlags() {
        val apps = listOf(
            app("com.one.app", "One", true),
            app("com.two.app", "Two", false),
            app("android.system", "System", true, system = true),
        )
        val flutterOnly = filterApps(apps, AppFilter(query = "", flutterOnly = true, hideSystem = true))
        assertEquals(listOf("com.one.app"), flutterOnly.map { it.packageName })

        val allUser = filterApps(apps, AppFilter(query = "", flutterOnly = false, hideSystem = true))
        assertEquals(listOf("com.one.app", "com.two.app"), allUser.map { it.packageName })

        val query = filterApps(apps, AppFilter(query = "TWO", flutterOnly = false, hideSystem = false))
        assertEquals(listOf("Two"), query.map { it.label })
    }

    @Test
    fun packageIdentifierValidationRejectsUrlsAndMalformedIds() {
        for (ok in listOf("com.example.app", "a.b", "com.example_app.one2")) {
            assertTrue("$ok should be a valid package id", PackageId.isValid(ok))
        }
        for (bad in listOf(
            "", "com", "com.", ".com", "com..app", "1com.app", "com.1app",
            "com.app/evil", "https://com.app", "com app", "com-app.app",
            "a".repeat(PackageId.MAX_LENGTH + 1),
        )) {
            assertFalse("$bad must be rejected", PackageId.isValid(bad))
        }
    }

    @Test
    fun webLinksAreOnlyHttpOrHttpsWithAHost() {
        assertEquals("https://pub.dev/packages/dio", safeWebUrl("https://pub.dev/packages/dio"))
        assertEquals("http://example.com/x", safeWebUrl(" http://example.com/x "))
        for (bad in listOf(
            null, "", "pub.dev", "javascript:alert(1)", "file:///etc/passwd",
            "ftp://example.com/a", "https://", "intent://scan",
        )) {
            assertNull("$bad must be rejected", safeWebUrl(bad))
        }
    }

    @Test
    fun byteSizesStayHonestForUnknownAndRealValues() {
        assertEquals(ReportMetadata.UNAVAILABLE, humanBytes(0))
        assertEquals(ReportMetadata.UNAVAILABLE, humanBytes(-5))
        assertEquals("999 B", humanBytes(999))
        assertEquals("2 KB", humanBytes(2048))
        assertEquals("5 MB", humanBytes(5L * 1024 * 1024))
        assertEquals("1.5 GB", humanBytes((1.5 * 1024 * 1024 * 1024).toLong()))
    }

    @Test
    fun routeTreeFlatteningIsPreOrderDepthFirstAndBounded() {
        val child = RouteNode(path = "/api/v1", label = "v1", terminal = true)
        val api = RouteNode(path = "/api", label = "api", children = listOf(child), terminal = false)
        val settings = RouteNode(path = "/settings", label = "settings", terminal = true)
        val rows = flattenRoutes(listOf(api, settings), maxRows = 10)
        assertEquals(listOf("/api", "/api/v1", "/settings"), rows.map { it.node.path })
        assertEquals(listOf(0, 1, 0), rows.map { it.depth })
        assertEquals(2, flattenRoutes(listOf(api, settings), maxRows = 2).size)
    }

    @Test
    fun exportChoiceDefaultsToEverySectionAndOptsIntoNothing() {
        val choice = ExportChoice()
        assertEquals(ReportExport.allSections, choice.sections)
        assertFalse("sensitive must be off by default", choice.sensitive)
        assertTrue(choice.json)
        assertEquals("json", choice.extension)
        assertEquals("md", choice.copy(json = false).extension)
        assertTrue(choice.canExport)

        val withoutFindings = choice.toggled(ReportSection.FINDINGS)
        assertFalse(ReportSection.FINDINGS in withoutFindings.sections)
        assertEquals(choice.sections, withoutFindings.toggled(ReportSection.FINDINGS).sections)

        assertFalse("empty selection must not export", ExportChoice(sections = emptySet()).canExport)
    }

    @Test
    fun tileMetadataKeepsTheSizeAndPutsTheSdkRangeOnItsOwnLine() {
        val base = app("com.example.app", "Example", true).copy(sizeBytes = 176L * 1024 * 1024, splitCount = 0)
        val lines = tileMetaLines(base)
        assertEquals("three metadata lines expected: $lines", 3, lines.size)
        assertTrue(lines[0], lines[0].contains("v1.0 (1)"))
        assertFalse("the version line must never share it with the SDK range", lines[0].contains("SDK"))
        // Whole range is one token: it cannot wrap between "SDK" and the numbers.
        assertEquals("SDK 26→35", lines[1])
        assertTrue("size must stay visible", lines[2].contains("176 MB"))
        assertFalse("zero splits must not be announced", lines[2].contains("split"))

        val splitLines = tileMetaLines(base.copy(splitCount = 3))
        assertTrue(splitLines.any { it.contains("3 split(s)") })
        assertTrue(splitLines.any { it.contains("176 MB") })
    }

    @Test
    fun theCollapsedFabExpandsIntoTheSearchField() {
        val collapsed = SearchUi()
        assertFalse(collapsed.expanded)
        assertFalse("an empty query must not claim to filter", collapsed.filtering)

        val expanded = collapsed.expand()
        assertTrue(expanded.expanded)
        assertTrue(expanded.typed("dio").filtering)
    }

    @Test
    fun collapsingKeepsTheQuerySoResultsStayFiltered() {
        val filtering = SearchUi(expanded = true, query = "dio")
        val collapsed = filtering.collapse()
        assertFalse(collapsed.expanded)
        assertEquals("collapse must not clear the query", "dio", collapsed.query)
        assertTrue("a collapsed query still filters the list", collapsed.filtering)

        // Closing with Back is the same transition, not a different one.
        assertEquals(collapsed, filtering.back())
    }

    @Test
    fun clearingEmptiesTheQueryAndKeepsTheFieldOpen() {
        val filtering = SearchUi(expanded = true, query = "dio")
        val cleared = filtering.cleared()
        assertTrue("the X resets the query, not the field", cleared.expanded)
        assertEquals("", cleared.query)
        assertFalse(cleared.filtering)
    }

    @Test
    fun backOnlyBelongsToTheFieldWhileItIsExpanded() {
        // Home: an open field collapses on the first Back, then the system exits.
        assertEquals(SearchUi(), SearchUi(expanded = true).back())
        // Collapsed: Back is not ours, so it must reach the system.
        assertNull("Back must not be consumed by a collapsed FAB", SearchUi().back())
        assertNull(SearchUi(query = "dio").back())
    }

    @Test
    fun theSearchMotionStaysInsideTheBriefBudget() {
        assertTrue("200–240 ms", SEARCH_DURATION_MS in 200..240)
    }

    @Test
    fun theToolsPanelEnablesThePackageScanOnlyForAValidIdAndAnIdleScanner() {
        val blank = advancedPanelState(packageInput = "", running = false, queueActive = false, appCount = 11)
        assertFalse("an empty id cannot start a scan", blank.scanPackageEnabled)
        assertNull("a blank field is not an error yet", blank.packageHint)
        assertFalse("no inline error means no error outline", blank.packageInvalid)

        val invalid = advancedPanelState(packageInput = "com", running = false, queueActive = false, appCount = 11)
        assertFalse(invalid.scanPackageEnabled)
        assertTrue(invalid.packageInvalid)
        assertEquals("Enter a dotted Android package id.", invalid.packageHint)

        val valid = advancedPanelState(packageInput = " com.example.app ", running = false, queueActive = false, appCount = 11)
        assertTrue("surrounding whitespace must not block a real id", valid.scanPackageEnabled)
        assertFalse(valid.packageInvalid)
        assertNull(valid.packageHint)

        val busy = advancedPanelState(packageInput = "com.example.app", running = true, queueActive = false, appCount = 11)
        assertFalse("one scan at a time", busy.scanPackageEnabled)
        assertNull("busy is not an input error", busy.packageHint)
    }

    @Test
    fun theToolsPanelSaysWhyScanAllCannotStart() {
        val ready = advancedPanelState("", running = false, queueActive = false, appCount = 11)
        assertTrue(ready.scanAllEnabled)
        assertEquals("11 apps · one at a time", ready.scanAllSubtitle)
        assertEquals("1 app · one at a time", advancedPanelState("", false, false, appCount = 1).scanAllSubtitle)

        val running = advancedPanelState("", running = true, queueActive = false, appCount = 11)
        assertFalse(running.scanAllEnabled)
        assertEquals("A scan is already running", running.scanAllSubtitle)

        val queue = advancedPanelState("", running = false, queueActive = true, appCount = 11)
        assertFalse("no second queue while one is active", queue.scanAllEnabled)
        assertEquals("A scan is already running", queue.scanAllSubtitle)

        val empty = advancedPanelState("", running = false, queueActive = false, appCount = 0)
        assertFalse(empty.scanAllEnabled)
        assertEquals("No Flutter apps to scan", empty.scanAllSubtitle)
    }

    @Test
    fun aMissingPackageMessageBeatsTheSyntaxHint() {
        val missing = advancedPanelState(
            packageInput = "com.example.app",
            running = false,
            queueActive = false,
            appCount = 11,
            packageError = "Package not installed or not in the cached list.",
        )
        assertTrue("the field is highlighted for a package that is not installed", missing.packageInvalid)
        assertEquals("Package not installed or not in the cached list.", missing.packageHint)
        assertTrue("a real id still keeps the action enabled", missing.scanPackageEnabled)
    }

    @Test
    fun dependencyFilteringAndPagingAreExplicit() {
        val deps = listOf("dio", "http", "path_provider", "flutter_secure_storage")
        assertEquals(deps, filterDependencies(deps, ""))
        assertEquals(listOf("path_provider"), filterDependencies(deps, "PRO"))
        assertTrue(filterDependencies(deps, "zzz").isEmpty())

        val many = (1..238).map { "package_$it" }
        assertEquals(60, dependencyPage(many, DEPENDENCY_PAGE).size)
        assertEquals(120, dependencyPage(many, DEPENDENCY_PAGE * 2).size)
        assertEquals(238, dependencyPage(many, Int.MAX_VALUE).size)
        assertTrue(dependencyPage(many, -5).isEmpty())
    }
}
