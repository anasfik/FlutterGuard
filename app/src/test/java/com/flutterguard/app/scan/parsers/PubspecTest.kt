package com.flutterguard.app.scan.parsers

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** `assets/flutter_assets/pubspec.yaml` is the APK's own dependency manifest. */
class PubspecTest {

    private val sample = """
        name: anx_reader
        description: An ebook reader
        version: 1.14.0+6321
        publish_to: 'none'

        environment:
          sdk: ">=3.0.0 <4.0.0"

        dependencies:
          flutter:
            sdk: flutter
          dio: ^5.4.0
          flutter_gemini: ^3.0.0   # google AI
          langchain_openai: 0.8.1+1
          shelf: ^1.4.1
          local_dep:
            path: ../local_dep

        dev_dependencies:
          flutter_test:
            sdk: flutter
          mockito: ^5.4.0

        flutter:
          uses-material-design: true
    """.trimIndent()

    @Test
    fun readsNameVersionAndFlatDependencies() {
        val info = Pubspec.parse(sample)
        assertEquals("anx_reader", info.name)
        assertEquals("1.14.0+6321", info.version)
        assertEquals("^5.4.0", info.deps["dio"])
        assertEquals("^3.0.0", info.deps["flutter_gemini"])
        assertEquals("0.8.1+1", info.deps["langchain_openai"])
    }

    @Test
    fun devDependenciesAndNestedStructuresAreNotDependencies() {
        val deps = Pubspec.parse(sample).deps
        assertFalse("dev deps leaked", deps.containsKey("mockito"))
        assertFalse("path dep leaked", deps.containsKey("local_dep"))
        assertFalse("nested sdk key leaked", deps.containsKey("sdk"))
        assertFalse("top-level key leaked as dep", deps.containsKey("environment"))
    }

    @Test
    fun missingFileIsEmptyNotAnError() {
        val info = Pubspec.parse("")
        assertTrue(info.isEmpty)
        assertNull(info.name)
        assertTrue(info.deps.isEmpty())
    }

    @Test
    fun dependencyCountIsBounded() {
        val many = buildString {
            appendLine("name: big")
            appendLine("dependencies:")
            for (i in 0 until 50) appendLine("  pkg_$i: ^1.0.0")
        }
        assertEquals(10, Pubspec.parse(many, maxDeps = 10).deps.size)
    }

    @Test
    fun nonsenseNamesAreRejected() {
        val junk = """
            name: Bad Name!
            dependencies:
              Capitalized: ^1.0.0
              ok_name: ^2.0.0
        """.trimIndent()
        val info = Pubspec.parse(junk)
        assertNull(info.name)
        assertEquals(setOf("ok_name"), info.deps.keys)
    }
}
