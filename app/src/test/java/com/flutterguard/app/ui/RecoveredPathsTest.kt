package com.flutterguard.app.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Recovered-path honesty: build-machine paths are never presented as routes or Dart source. */
class RecoveredPathsTest {

    private val cargo = "/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/qcms-0.3.0/src/"

    @Test
    fun cargoRegistryPathsAreEmbeddedBuildPaths() {
        assertEquals(RecoveredKind.EMBEDDED_BUILD, RecoveredPaths.kind(cargo))
        assertEquals(RecoveredKind.EMBEDDED_BUILD, RecoveredPaths.kind("/Users/dev/build/flutter/lib/x.so"))
        assertEquals(RecoveredKind.EMBEDDED_BUILD, RecoveredPaths.kind("/root/.pub-cache/hosted/pub.dev/dio-5.4.0/lib/dio.dart"))
        assertEquals(RecoveredKind.EMBEDDED_BUILD, RecoveredPaths.kind("C:\\Users\\dev\\flutter\\bin\\cache\\dart-sdk"))
        assertEquals(RecoveredKind.EMBEDDED_BUILD, RecoveredPaths.kind("/rustc/abc123/library/std/src/io/mod.rs"))
    }

    @Test
    fun dartSourcesAndRoutesKeepTheirOwnKind() {
        assertEquals(RecoveredKind.DART_SOURCE, RecoveredPaths.kind("/data/user/0/app/lib/src/state.dart"))
        assertEquals(RecoveredKind.ROUTE, RecoveredPaths.kind("/api/v1/player"))
        assertEquals(RecoveredKind.ROUTE, RecoveredPaths.kind("/profile"))
        assertFalse(RecoveredPaths.isBuildPath("/api/v1/player"))
    }

    @Test
    fun splitSeparatesBuildPathsOutOfRoutesAndSources() {
        val groups = RecoveredPaths.split(
            routes = listOf(cargo, "/api/v1", "/home/runner/.cargo/registry/src/index.crates.io-x/tokio-1.0/src", "/settings"),
            dartSources = listOf("/data/app/lib/main.dart", "/Users/ci/work/build/lib/app.dart"),
        )
        assertEquals(listOf("/api/v1", "/settings"), groups.routes)
        assertEquals(listOf("/data/app/lib/main.dart"), groups.dartSources)
        assertEquals(
            listOf(cargo, "/home/runner/.cargo/registry/src/index.crates.io-x/tokio-1.0/src", "/Users/ci/work/build/lib/app.dart"),
            groups.buildPaths,
        )
    }

    @Test
    fun splitIsDistinctAndOrderPreserving() {
        val groups = RecoveredPaths.split(
            routes = listOf("/a", "/a", "/home/x/y.cargo/z"),
            dartSources = listOf("/a", "/a"),
        )
        assertEquals(listOf("/a"), groups.routes)
        assertEquals(emptyList<String>(), groups.dartSources)
        assertEquals(listOf("/home/x/y.cargo/z"), groups.buildPaths)
    }

    @Test
    fun unknownPathShapesNeverBecomeRoutes() {
        // Review LOW: anything that was not a known build root defaulted to ROUTE.
        assertEquals(RecoveredKind.UNCLASSIFIED, RecoveredPaths.kind("build/flutter_assets"))
        assertEquals(RecoveredKind.EMBEDDED_BUILD, RecoveredPaths.kind("/opt/build/flutter/x"))
        assertEquals(RecoveredKind.UNCLASSIFIED, RecoveredPaths.kind("/data/app/lib/state.rs"))

        val groups = RecoveredPaths.split(
            routes = listOf("build/flutter_assets", "/opt/build/flutter/x", "/api/v1/player"),
            dartSources = emptyList(),
        )
        assertEquals(listOf("/api/v1/player"), groups.routes)
        assertEquals(listOf("build/flutter_assets"), groups.unclassified)
        assertEquals(listOf("/opt/build/flutter/x"), groups.buildPaths)
    }

    @Test
    fun compactKeepsTheMeaningfulTailOnOneLine() {
        // Device defect 1: the tutorial path above rendered as five wrapped lines.
        assertEquals("…/qcms-0.3.0/src/", RecoveredPaths.compact(cargo))
        assertEquals("…/auth/state.dart", RecoveredPaths.compact("/data/app/lib/src/features/auth/state.dart"))
        assertFalse(RecoveredPaths.compact(cargo).contains("\n"))
    }

    @Test
    fun compactLeavesShortPathsAlone() {
        assertEquals("/api/v1", RecoveredPaths.compact("/api/v1"))
        assertEquals("/profile", RecoveredPaths.compact("/profile"))
        assertEquals("", RecoveredPaths.compact(""))
        assertEquals("/legal/privacy/", RecoveredPaths.compact("/legal/privacy/"))
    }

    @Test
    fun compactBoundsAbsurdlyLongSegments() {
        val compact = RecoveredPaths.compact("/a/" + "x".repeat(400), maxChars = 48)
        assertTrue("length ${compact.length}", compact.length <= 48)
        assertTrue(compact.startsWith("…"))
    }
}
