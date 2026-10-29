package com.flutterguard.app.scan

import com.flutterguard.app.scan.rules.sourcePathExtensions

/**
 * One node of the recovered-route tree. [path] is the literal prefix joined
 * from the recovered strings; [terminal] marks a path that was itself recovered.
 * Grouping is prefix bookkeeping only — no navigation edge is implied.
 */
data class RouteNode(
    val path: String,
    val label: String,
    val children: List<RouteNode> = emptyList(),
    val terminal: Boolean = false,
)

/**
 * Deterministic, bounded grouping of candidate route strings. Malformed
 * entries (trailing/double slashes, traversal, whitespace, absolute URLs,
 * source/build paths) are dropped, never repaired. Limits are explicit and
 * must not be mistaken for full coverage.
 */
object RouteTree {

    fun build(
        routes: Collection<String>,
        maxDepth: Int = 8,
        maxNodes: Int = 256,
        maxChildren: Int = 32,
    ): List<RouteNode> {
        val parsed = routes.mapNotNull { parse(it, maxDepth) }
            .distinct()
            .sortedBy { it.joinToString("/") }
        val roots = sortedMapOf<String, MutableNode>()
        for (segs in parsed) {
            var level = roots
            var node: MutableNode? = null
            var path = ""
            for (seg in segs) {
                path += "/$seg"
                val n = level.getOrPut(seg) { MutableNode(path, seg) }
                node = n
                level = n.children
            }
            node?.terminal = true
        }

        val budget = intArrayOf(maxNodes)
        val out = ArrayList<RouteNode>()
        for (m in roots.values) {
            if (out.size >= maxChildren || budget[0] <= 0) break
            out.add(convert(m, budget, maxChildren))
        }
        return out
    }

    private fun convert(m: MutableNode, budget: IntArray, maxChildren: Int): RouteNode {
        budget[0]--
        val kids = ArrayList<RouteNode>()
        for (c in m.children.values) {
            if (kids.size >= maxChildren || budget[0] <= 0) break
            kids.add(convert(c, budget, maxChildren))
        }
        return RouteNode(m.path, m.label, kids, m.terminal)
    }

    private fun parse(route: String, maxDepth: Int): List<String>? {
        if (!route.startsWith("/") || route.startsWith("//")) return null
        if (route.any { it.isWhitespace() } || route.contains('\\') || route.contains("://")) return null
        val parts = route.split('/').drop(1)
        if (parts.isEmpty() || parts.any { it.isEmpty() || it == "." || it == ".." }) return null
        if (parts.size > maxDepth) return null
        val last = parts.last().lowercase()
        if (sourcePathExtensions.any { last.endsWith(it) }) return null
        return parts
    }

    private class MutableNode(val path: String, val label: String) {
        var terminal: Boolean = false
        val children = sortedMapOf<String, MutableNode>()
    }
}
