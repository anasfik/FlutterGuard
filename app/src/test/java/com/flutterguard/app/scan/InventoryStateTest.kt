package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Inventory cache rules: reuse across navigation, explicit refresh, visible failures. */
class InventoryStateTest {

    private val app = InstalledApp(
        packageName = "com.example.app",
        label = "Example",
        versionName = "1.2.3",
        versionCode = 7,
        minSdk = 26,
        targetSdk = 35,
        isFlutter = true,
        isSystem = false,
        sizeBytes = 3_000_000,
        splitCount = 1,
        icon = null,
    )

    @Test
    fun firstLoadMovesFromLoadingToReady() {
        val began = InventoryState().begin()
        assertTrue(began!!.loading)
        assertNull(began.error)
        assertFalse(began.hasData)

        val loaded = began.loaded(listOf(app), 1_000)
        assertFalse(loaded.loading)
        assertTrue(loaded.hasData)
        assertNull(loaded.error)
        assertEquals(listOf(app), loaded.apps)
        assertEquals(1_000L, loaded.loadedAtMs)
    }

    @Test
    fun refreshIsIgnoredWhileALoadIsInFlight() {
        val loading = InventoryState().begin()!!
        assertNull(loading.begin())
    }

    @Test
    fun discoveryFailureKeepsPreviousInventoryAndSurfacesTheError() {
        val ready = InventoryState().loaded(listOf(app), 1_000)
        val failed = ready.begin()!!.failed("Package manager unavailable")
        assertEquals(listOf(app), failed.apps)
        assertTrue(failed.hasData)
        assertFalse(failed.loading)
        assertEquals("Package manager unavailable", failed.error)

        val recovered = failed.begin()!!.loaded(listOf(app), 2_000)
        assertNull(recovered.error)
    }

    @Test
    fun failureWithNoPreviousInventoryIsNotAnEmptySuccess() {
        val failed = InventoryState().begin()!!.failed("boom")
        assertFalse(failed.hasData)
        assertTrue(failed.apps.isEmpty())
        assertEquals("boom", failed.error)
    }

    @Test
    fun tileSizeMetadataSumsBaseAndSplitsAndIgnoresMissingFiles() {
        val dir = createTempDir("fg-size")
        try {
            val base = File(dir, "base.apk").apply { writeBytes(ByteArray(100)) }
            val split = File(dir, "split_config.arm64_v8a.apk").apply { writeBytes(ByteArray(50)) }
            assertEquals(150L, totalApkBytes(base.path, arrayOf(split.path)))
            assertEquals(100L, totalApkBytes(base.path, null))
            assertEquals(100L, totalApkBytes(base.path, arrayOf(File(dir, "gone.apk").path)))
            assertEquals(0L, totalApkBytes(null, null))
        } finally {
            dir.deleteRecursively()
        }
    }
}
