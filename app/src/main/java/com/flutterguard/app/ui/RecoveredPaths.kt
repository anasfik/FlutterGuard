package com.flutterguard.app.ui

/**
 * Honest classification of a recovered path string. Absolute build-machine
 * paths found in native libraries (Cargo registry, Flutter SDK caches, CI
 * workdirs) are not routes and not Dart source: presenting them as either
 * invents a navigation graph the evidence does not support.
 */
enum class RecoveredKind { DART_SOURCE, EMBEDDED_BUILD, ROUTE, UNCLASSIFIED }

/** Recovered strings grouped by what they really are. */
data class RecoveredPathGroups(
    val routes: List<String> = emptyList(),
    val dartSources: List<String> = emptyList(),
    val buildPaths: List<String> = emptyList(),
    /** Path-shaped strings that are neither routes nor known build roots; never fed to the route tree. */
    val unclassified: List<String> = emptyList(),
)

object RecoveredPaths {

    /** Tail segments kept in a one-line row; two keeps `…/qcms-0.3.0/src/`. */
    const val DISPLAY_SEGMENTS = 2
    const val DISPLAY_MAX_CHARS = 64

    private val buildRoots = listOf(
        "/home/", "/Users/", "/root/", "/private/var/", "/var/folders/", "/srv/",
        "/opt/", "/usr/", "/var/", "/tmp/", "/etc/", "/mnt/", "/media/", "/proc/", "/sys/",
    )
    private val buildMarkers = listOf(
        "/.cargo/", "/.rustup/", "/rustc/", "/.pub-cache/", "/.gradle/", "/.dart_tool/",
        "/flutter/bin/cache", "index.crates.io-",
    )
    /** Source/binary suffixes: path-shaped, never a navigable route. */
    private val pathExtensions = listOf(
        ".rs", ".so", ".dylib", ".dll", ".h", ".hpp", ".c", ".cc", ".cpp", ".go", ".kt", ".java",
        ".gradle", ".json", ".yaml", ".yml", ".toml", ".lock", ".podspec", ".swift", ".m", ".mm",
        ".js", ".ts", ".css", ".html", ".xml",
    )
    private val windowsDrive = Regex("^[A-Za-z]:/")

    fun kind(raw: String): RecoveredKind {
        val path = raw.trim().replace('\\', '/')
        if (path.isEmpty()) return RecoveredKind.ROUTE
        val build = windowsDrive.containsMatchIn(path) ||
            buildRoots.any { path.startsWith(it) } ||
            buildMarkers.any { path.contains(it) }
        val lower = path.lowercase()
        return when {
            build -> RecoveredKind.EMBEDDED_BUILD
            lower.endsWith(".dart") -> RecoveredKind.DART_SOURCE
            // Routes are absolute app paths; a relative path with a slash or a
            // source/binary suffix is not navigation evidence.
            !path.startsWith("/") && path.contains('/') -> RecoveredKind.UNCLASSIFIED
            pathExtensions.any { lower.endsWith(it) } -> RecoveredKind.UNCLASSIFIED
            else -> RecoveredKind.ROUTE
        }
    }

    fun isBuildPath(raw: String): Boolean = kind(raw) == RecoveredKind.EMBEDDED_BUILD

    /**
     * One-line display form: the leading noise is dropped and the meaningful
     * tail kept (`/home/runner/.cargo/.../qcms-0.3.0/src/` → `…/qcms-0.3.0/src/`).
     * Rows must also set `maxLines = 1`; this helper only bounds the text.
     */
    fun compact(raw: String, segments: Int = DISPLAY_SEGMENTS, maxChars: Int = DISPLAY_MAX_CHARS): String {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return ""
        val slash = trimmed.replace('\\', '/')
        val trailingSlash = slash.length > 1 && slash.endsWith("/")
        val parts = slash.split('/').filter { it.isNotEmpty() }
        if (parts.isEmpty()) return trimmed
        val keep = maxOf(1, segments)

        if (parts.size <= keep) {
            val out = (if (slash.startsWith("/")) "/" else "") + parts.joinToString("/") +
                if (trailingSlash) "/" else ""
            return if (out.length <= maxChars) out else "…" + out.takeLast(maxChars - 1)
        }

        var kept = parts.takeLast(keep)
        fun render(): String = "…/" + kept.joinToString("/") + if (trailingSlash) "/" else ""
        var out = render()
        while (out.length > maxChars && kept.size > 1) {
            kept = kept.drop(1)
            out = render()
        }
        if (out.length > maxChars) out = "…/" + kept.last().takeLast((maxChars - 2).coerceAtLeast(1))
        return out
    }

    /**
     * Splits recovered route/source strings into routes, Dart sources and
     * embedded build paths. Order and distinctness are preserved; nothing is
     * invented, dropped or reordered.
     */
    fun split(routes: Collection<String>, dartSources: Collection<String>): RecoveredPathGroups {
        val plainRoutes = LinkedHashSet<String>()
        val dart = LinkedHashSet<String>()
        val build = LinkedHashSet<String>()
        val unknown = LinkedHashSet<String>()
        fun add(raw: String) {
            when (kind(raw)) {
                RecoveredKind.EMBEDDED_BUILD -> build.add(raw)
                RecoveredKind.DART_SOURCE -> dart.add(raw)
                RecoveredKind.ROUTE -> plainRoutes.add(raw)
                RecoveredKind.UNCLASSIFIED -> unknown.add(raw)
            }
        }
        for (raw in routes) add(raw)
        // The source list can contain misclassified strings; re-classify by kind.
        for (raw in dartSources) add(raw)
        return RecoveredPathGroups(plainRoutes.toList(), dart.toList(), build.toList(), unknown.toList())
    }
}
