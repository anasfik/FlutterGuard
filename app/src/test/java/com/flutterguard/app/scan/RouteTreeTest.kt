package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Route grouping is prefix bookkeeping only: literal paths preserved, no
 * invented edges, bounded output, malformed input rejected.
 */
class RouteTreeTest {

    @Test
    fun groupsByLiteralPrefixAndKeepsFullPaths() {
        val tree = RouteTree.build(
            listOf("/api/v1/users", "/api/v1/orders", "/api/v2/users", "/settings/profile"),
        )
        val api = tree.single { it.label == "api" }
        assertFalse("branch node must not claim a recovered route", api.terminal)
        assertEquals("/api", api.path)
        val v1 = api.children.single { it.label == "v1" }
        assertEquals(listOf("/api/v1/orders", "/api/v1/users"), v1.children.map { it.path })
        assertTrue(v1.children.all { it.terminal })
        val settings = tree.single { it.label == "settings" }
        assertEquals("/settings/profile", settings.children.single().path)
    }

    @Test
    fun aRouteThatIsAlsoAPrefixStaysTerminalWithChildren() {
        val tree = RouteTree.build(listOf("/api", "/api/v1"))
        val api = tree.single()
        assertTrue("/api must be terminal", api.terminal)
        assertEquals("/api", api.path)
        assertTrue(api.children.single().terminal)
    }

    @Test
    fun duplicatesCollapseToOneTerminal() {
        val tree = RouteTree.build(listOf("/api/v1", "/api/v1", "/api/v1"))
        val api = tree.single()
        assertEquals(1, api.children.size)
        assertTrue(api.children.single().terminal)
    }

    @Test
    fun malformedSlashFormsAreRejected() {
        val tree = RouteTree.build(
            listOf("api/v1", "/api//v1", "/api/v1/", "/", "", "  /api  ", "https://example.com/api", "package:app/main"),
        )
        assertTrue("malformed entries must not produce nodes: $tree", tree.isEmpty())
    }

    @Test
    fun traversalAndNonPathSegmentsAreRejected() {
        val tree = RouteTree.build(
            listOf("/../etc/passwd", "/api/../admin", "/a/./b", "/C:\\windows", "/a b/c", "/api/seg /x"),
        )
        assertTrue("traversal/noise must not produce nodes: $tree", tree.isEmpty())
    }

    @Test
    fun parameterSegmentsArePreservedLiterally() {
        val tree = RouteTree.build(listOf("/api/users/{id}", "/api/users/:user-id", "/files/*"))
        val api = tree.single { it.label == "api" }
        val users = api.children.single()
        assertEquals(setOf("{id}", ":user-id"), users.children.map { it.label }.toSet())
        assertTrue(users.children.all { it.terminal && it.path.startsWith("/api/users/") })
        assertEquals("/files/*", tree.single { it.label == "files" }.children.single().path)
    }

    @Test
    fun sourcePathsAreRejected() {
        val tree = RouteTree.build(listOf("/lib/main.dart", "/api/users/Handler.java", "/assets/Font.ttf"))
        assertTrue("source/build paths must not be grouped: $tree", tree.isEmpty())
    }

    @Test
    fun depthLimitIsExplicitAndOverlongRoutesAreDropped() {
        val deep = "/" + (1..9).joinToString("/") { "seg$it" } // 9 segments
        val tree = RouteTree.build(listOf("/api/v1", deep), maxDepth = 8)
        assertEquals("depth cap must drop, not truncate", 1, tree.size)
        assertEquals("/api", tree.single().path)
    }

    @Test
    fun nodeLimitIsExplicitAndDeterministic() {
        val routes = (1..10).map { "/group$it/path" }
        val tree = RouteTree.build(routes, maxNodes = 6)
        var nodes = 0
        fun count(n: RouteNode) { nodes++; n.children.forEach { count(it) } }
        tree.forEach { count(it) }
        assertTrue("node cap exceeded: $nodes", nodes <= 6)
        // Deterministic: input order must not change the tree.
        assertEquals(tree, RouteTree.build(routes.reversed(), maxNodes = 6))
    }

    @Test
    fun childLimitIsExplicitAndKeepsAlphabeticallyFirstChildren() {
        val routes = (1..10).map { "/g/item${'a' + it}" }
        val tree = RouteTree.build(routes, maxChildren = 3)
        val g = tree.single()
        assertEquals(3, g.children.size)
        assertEquals(listOf("itemb", "itemc", "itemd"), g.children.map { it.label })
    }

    @Test
    fun outputIsDeterministicRegardlessOfInputOrder() {
        val a = listOf("/b/one", "/a/two", "/a/one", "/c/x")
        assertEquals(RouteTree.build(a), RouteTree.build(a.reversed()))
    }
}
