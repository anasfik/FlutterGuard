package com.flutterguard.app.ui

import com.flutterguard.app.scan.HostInfo

/**
 * One recovered host, with the URL a row would open. [verified] is false for
 * strings that only look like hosts (concatenation artifacts such as
 * `appflowy.comworkspace`, localhost, IPs, malformed values): they stay visible
 * as unverified candidates but never get an Open action.
 */
data class EndpointRow(
    val host: HostInfo,
    val displayUrl: String,
    val url: String?,
    val verified: Boolean,
)

/**
 * A3/A4: the Open action must open exactly the validated URL the row shows.
 * A host is trusted only when it is a plausible public DNS name; anything else
 * is demoted instead of being presented as an app-owned endpoint.
 */
object Endpoints {

    /**
     * Public suffixes Flutter/Android apps actually use. Deliberately a table,
     * not a heuristic: `appflowy.comworkspace` must fail, and an unknown suffix
     * must not be silently promoted to a verified endpoint.
     */
    val TRUSTED_TLDS: Set<String> = setOf(
        // generic
        "com", "org", "net", "io", "dev", "app", "cloud", "co", "ai", "me", "info", "biz",
        "tv", "gg", "sh", "fm", "ly", "to", "xyz", "site", "online", "tech", "store", "blog",
        "news", "live", "page", "link", "space", "wiki", "press", "network", "systems",
        "software", "digital", "studio", "design", "tools", "works", "world", "today", "media",
        "video", "music", "art", "fun", "games", "email", "social", "community", "foundation",
        "academy", "school", "money", "finance", "market", "shop", "club", "host", "zone",
        "group", "team", "life", "center", "global", "support", "services", "solutions",
        "ventures", "capital", "partners", "limited", "ltd", "inc", "mobi", "name", "pro",
        "travel", "edu", "gov", "mil", "int",
        // country
        "us", "uk", "de", "fr", "nl", "se", "no", "es", "it", "pl", "ru", "jp", "cn", "in",
        "au", "ca", "br", "ch", "at", "be", "dk", "fi", "ie", "nz", "sg", "hk", "kr", "tw",
        "tr", "mx", "ar", "cl", "za", "ae", "il", "pt", "cz", "gr", "hu", "ro", "sk", "ua", "eu",
        // ccTLDs recovered hosts actually used; hiding them was a recall loss
        "id", "my", "cc", "so", "ws", "top",
    )

    /** Reverse-DNS roots: their presence as the first label means "package id", not host. */
    private val PACKAGE_ROOTS = setOf("com", "org", "net", "android", "androidx", "edu", "gov", "mil", "int")

    fun row(host: HostInfo): EndpointRow {
        val name = host.host.trim()
        // A recovered URL sample is proof even for a package-id-shaped string.
        val sample = host.samples.firstNotNullOfOrNull { safeWebUrl(it) }
        val trusted = isTrustedHost(name, provenBySample = sample != null)
        val url = when {
            !trusted -> null
            sample != null -> sample
            else -> safeWebUrl("https://$name")
        }
        return EndpointRow(
            host = host,
            displayUrl = url ?: name,
            url = url,
            verified = trusted && url != null,
        )
    }

    /** Verified hosts first; every recovered host stays visible. */
    fun rows(hosts: List<HostInfo>): List<EndpointRow> {
        val all = hosts.filter { it.host.isNotBlank() }.map { row(it) }
        return all.filter { it.verified } + all.filterNot { it.verified }
    }

    /**
     * Plausible public host: no scheme/path/space/port noise, not localhost or a
     * private/IP literal, at least two labels, and a known public suffix.
     *
     * A dotted string with a reverse-DNS root (`com.example.app`,
     * `androidx.core.app`, `com.bzta.my`) is a package id, not an endpoint; it
     * only counts as a host when a real http(s) sample proves it.
     */
    fun isTrustedHost(raw: String, provenBySample: Boolean = false): Boolean {
        val name = raw.trim().lowercase()
        if (name.isEmpty() || name.length > 253) return false
        if (name.any { it.isWhitespace() || it == '/' || it == '\\' || it == '@' || it == '?' || it == '#' || it == ':' }) return false
        if (name.startsWith(".") || name.endsWith(".") || name.contains("..")) return false
        // IP literals and localhost/private names are not openable research endpoints.
        if (name.all { it.isDigit() || it == '.' }) return false
        if (name == "localhost" || name.endsWith(".localhost") || name.endsWith(".local")) return false
        if (name.startsWith("127.") || name.startsWith("10.") || name.startsWith("192.168.")) return false
        val labels = name.split('.')
        if (labels.size < 2) return false
        if (labels.any { label -> label.isEmpty() || label.length > 63 || !label.all { it.isLetterOrDigit() || it == '-' } }) return false
        if (labels.any { it.startsWith("-") || it.endsWith("-") }) return false
        if (labels.last() !in TRUSTED_TLDS) return false
        if (!provenBySample && labels.size >= 3 && labels.first() in PACKAGE_ROOTS) return false
        return true
    }
}
