package com.flutterguard.app.legal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import com.flutterguard.app.ui.Markdown
import com.flutterguard.app.ui.MdBlock
import java.io.File

/**
 * The Play listing hosts docs/legal (Markdown); the app renders the copies under
 * assets/legal. They must be the same bytes, and the content must describe what
 * the code actually does (offline, consent-gated inventory, deletion, contact).
 */
class LegalDocsTest {

    private fun asset(name: String) = File("src/main/assets/legal/$name.md")

    private fun published(name: String) = File("../docs/legal/$name.md")

    @Test
    fun assetAndPublishedCopiesAreByteIdentical() {
        for (name in listOf("privacy", "security")) {
            val asset = asset(name)
            val published = published(name)
            assertTrue("missing ${asset.path}", asset.isFile)
            assertTrue("missing ${published.path}", published.isFile)
            assertEquals(
                "$name.md must be byte-identical in assets/legal and docs/legal",
                asset.readBytes().toList(),
                published.readBytes().toList(),
            )
        }
    }

    @Test
    fun documentsCoverThePlayRequiredSections() {
        val privacy = asset("privacy").readText()
        val required = listOf(
            "no network permission",
            "QUERY_ALL_PACKAGES",
            "telemetry",
            "app-specific storage",
            "FileProvider",
            "Retention and deletion",
            "Delete all reports",
            "Children",
            "Changes",
            "Contact",
            "Effective date",
        )
        for (needle in required) {
            assertTrue("privacy.md is missing: $needle", privacy.contains(needle, ignoreCase = true))
        }
    }

    @Test
    fun bundledDocumentsRenderWithTheRealParser() {
        for (name in listOf("privacy", "security")) {
            val blocks = Markdown.parse(asset(name).readText())
            assertTrue("$name.md produced too few blocks", blocks.size > 20)
            assertTrue("$name.md has no headings", blocks.any { it is MdBlock.Heading })
            assertTrue("$name.md has no bullets", blocks.any { it is MdBlock.Bullet })
        }
    }

    @Test
    fun securityDocumentStatesTheBoundaries() {
        val security = asset("security").readText()
        for (needle in listOf(
            "INTERNET",
            "Foreground",
            "FLAG_SECURE",
            "file-pick",
            "Known limitations",
            "Reporting a vulnerability",
        )) {
            assertTrue("security.md is missing: $needle", security.contains(needle, ignoreCase = true))
        }
        assertTrue("documents must not be placeholders", security.length > 2000)
        assertTrue("documents must not be placeholders", asset("privacy").length() > 2000)
    }
}
