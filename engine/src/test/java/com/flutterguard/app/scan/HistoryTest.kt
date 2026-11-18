package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HistoryTest {

    private val before = listOf(
        "version:5.0.0 (42)",
        "hosts:api.invidious.io|song.link|www.youtube.com",
        "routes:/api/v1|/v1/player",
        "findings:HIGH|MAN-CLEARTEXT|MEDIUM|MAN-BACKUP",
        "deps:dio|irondash_engine_context|jiosaavn",
    ).joinToString("\n")

    private val after = listOf(
        "version:5.1.2 (45)",
        "hosts:www.youtube.com|www.jiosaavn.com",
        "routes:/api/v1|/api/skipSegments",
        "findings:HIGH|MAN-CLEARTEXT|HIGH|SEC-KEY-GOOGLE",
        "deps:dio|smtc_windows",
    ).joinToString("\n")

    @Test
    fun reportsVersionAndMembershipChanges() {
        val lines = History.diff(before, after)
        assertEquals("~ version 5.0.0 (42) → 5.1.2 (45)", lines.first())
        assertTrue(lines.contains("- host api.invidious.io"))
        assertTrue(lines.contains("- host song.link"))
        assertTrue(lines.contains("+ host www.jiosaavn.com"))
        assertTrue(lines.contains("- route /v1/player"))
        assertTrue(lines.contains("+ route /api/skipSegments"))
        assertTrue(lines.contains("- finding MEDIUM|MAN-BACKUP"))
        assertTrue(lines.contains("+ finding HIGH|SEC-KEY-GOOGLE"))
        assertTrue(lines.contains("- dep irondash_engine_context"))
        assertTrue(lines.contains("+ dep smtc_windows"))
        // unchanged entries must not appear
        assertTrue(lines.none { it.contains("www.youtube.com") })
        assertTrue(lines.none { it.contains("/api/v1") })
    }

    @Test
    fun saysSoWhenNothingChanged() {
        val lines = History.diff(before, before)
        assertEquals(1, lines.size)
        assertTrue(lines.first().startsWith("no change"))
    }

    @Test
    fun capsTheNumberOfLines() {
        val hosts = (1..20).joinToString("|") { "h$it.example" }
        val routes = (1..20).joinToString("|") { "/r$it" }
        val findings = (1..20).joinToString("|") { "LOW|F$it" }
        val deps = (1..20).joinToString("|") { "d$it" }
        val old = "version:1 (1)\nhosts:\nroutes:\nfindings:\ndeps:"
        val new = "version:1 (1)\nhosts:$hosts\nroutes:$routes\nfindings:$findings\ndeps:$deps"
        val lines = History.diff(old, new)
        assertTrue("diff grew to ${lines.size} lines", lines.size <= 40)
        assertTrue(lines.last(), lines.last().contains("more"))
    }
}
