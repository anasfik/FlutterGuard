package com.flutterguard.app.scan.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The filename-only inventory is the cheapest signal in the scan, so it has to be
 * exact: a wrong marker claims an SDK the app does not ship, and a wrong config
 * list sends a researcher to a file that is not there.
 */
class AssetInventoryTest {

    @Test
    fun bundledHtmlAndScriptsAreCounted() {
        val r = AssetInventory.evaluate(
            setOf(
                "assets/flutter_assets/assets/foliate-js/index.html",
                "assets/flutter_assets/assets/foliate-js/src/view.js",
                "assets/flutter_assets/assets/foliate-js/epub.js",
                "assets/flutter_assets/AssetManifest.json",
            ),
        )
        assertEquals(1, r.webPayloads.size)
        assertTrue(r.webPayloads[0].endsWith("index.html"))
        assertEquals(2, r.scriptCount)
    }

    @Test
    fun rootPropertiesFilesNameTheSdkTheyProve() {
        val r = AssetInventory.evaluate(
            setOf(
                "billing.properties",
                "transport-runtime.properties",
                "play-services-basement.properties",
                "assets/flutter_assets/foo.properties",
            ),
        )
        assertEquals(setOf("Google Play Billing", "Google DataTransport (Firebase)", "Google Play Services"), r.sdkMarkers.keys)
        assertEquals(listOf("billing.properties"), r.sdkMarkers["Google Play Billing"])
        // A .properties file under assets/ is not an SDK marker.
        assertTrue(r.sdkMarkers.values.flatten().none { it.startsWith("assets/") })
    }

    @Test
    fun configFilesAreListedButResourcesAndFontsAreNot() {
        val r = AssetInventory.evaluate(
            setOf(
                "assets/flutter_assets/env/prod.env",
                "assets/flutter_assets/config/app.yaml",
                "assets/flutter_assets/fonts/Roboto.ttf",
                "assets/flutter_assets/packages/cached_network_image/x.json",
                "res/raw/keys.json",
                "META-INF/services/x.json",
                "classes.dex",
            ),
        )
        assertEquals(
            listOf("assets/flutter_assets/config/app.yaml", "assets/flutter_assets/env/prod.env"),
            r.configFiles,
        )
    }

    @Test
    fun anEmptyApkProducesAnEmptyInventory() {
        val r = AssetInventory.evaluate(emptySet())
        assertTrue(r.webPayloads.isEmpty())
        assertTrue(r.configFiles.isEmpty())
        assertTrue(r.sdkMarkers.isEmpty())
        assertEquals(0, r.scriptCount)
    }

    @Test
    fun listingIsBounded() {
        val many = (1..200).map { "assets/flutter_assets/page$it.html" }.toSet()
        val r = AssetInventory.evaluate(many, maxEach = 10)
        assertEquals(10, r.webPayloads.size)
    }
}
