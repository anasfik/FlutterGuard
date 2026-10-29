package com.flutterguard.app.scan

/**
 * Dependency row for the UI/export. [url] is only produced for a validated
 * pub.dev package name; version/license stay null when not actually recovered.
 */
data class DependencyInfo(
    val name: String,
    val url: String?,
    val provenance: String = "",
    val version: String? = null,
    val license: String? = null,
)

/**
 * pub.dev package-name rules: ASCII lowercase letter first, then lowercase
 * letters/digits/underscore, length 1..64. No network access, no invented URLs.
 */
object PubPackage {

    private val valid = Regex("^[a-z][a-z0-9_]{0,63}$")

    fun isValid(name: String): Boolean = valid.matches(name)

    fun url(name: String): String? = if (isValid(name)) "https://pub.dev/packages/$name" else null

    fun describe(
        name: String,
        provenance: String = "",
        version: String? = null,
        license: String? = null,
    ): DependencyInfo = DependencyInfo(name, url(name), provenance, version, license)
}
