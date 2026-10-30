package com.flutterguard.app.scan.rules

/**
 * Filename-only inventory of an APK.
 *
 * Three things in a Flutter release build can be named without reading a byte:
 * bundled HTML/JS payloads a WebView will render, root-level Gradle `.properties`
 * files that prove which Google SDKs were linked, and config/secret-bearing
 * assets worth opening by hand.
 *
 * Nothing here reads content, so no value can leak and no scrubbing is needed.
 * Note for future edits: never write a `star-star` wildcard inside this KDoc —
 * it opens a nested block comment in Kotlin and silently comments out the file.
 */
object AssetInventory {

    data class Result(
        val webPayloads: List<String> = emptyList(),
        val scriptCount: Int = 0,
        val configFiles: List<String> = emptyList(),
        val sdkMarkers: Map<String, List<String>> = emptyMap(),
    )

    /** Root-level properties written by the Android Gradle plugin per linked SDK. */
    private val sdkMarkerFiles = linkedMapOf(
        "billing.properties" to "Google Play Billing",
        "firebase-encoders.properties" to "Firebase (encoders)",
        "firebase-encoders-json.properties" to "Firebase (encoders)",
        "firebase-encoders-proto.properties" to "Firebase (encoders)",
        "play-services-base.properties" to "Google Play Services",
        "play-services-basement.properties" to "Google Play Services",
        "play-services-tasks.properties" to "Google Play Services",
        "play-services-location.properties" to "Google Play Services (location)",
        "play-services-places-placereport.properties" to "Google Play Services (places)",
        "transport-api.properties" to "Google DataTransport (Firebase)",
        "transport-backend-cct.properties" to "Google DataTransport (Firebase)",
        "transport-runtime.properties" to "Google DataTransport (Firebase)",
    )

    private val configExt = setOf(
        "env", "json", "yaml", "yml", "toml", "properties", "ini", "cfg",
        "pem", "key", "crt", "p12", "pfx", "jks", "keystore", "bks",
        "sqlite", "db", "realm", "graphql", "proto",
    )

    private val noisePath = listOf("/res/", "/META-INF/", "/lib/", "flutter_assets/fonts/", "flutter_assets/packages/")

    fun evaluate(zipNames: Set<String>, maxEach: Int = 40): Result {
        val web = ArrayList<String>()
        val config = ArrayList<String>()
        val markers = LinkedHashMap<String, MutableList<String>>()
        var scripts = 0

        for (name in zipNames) {
            val lower = name.lowercase()
            if (lower.endsWith(".properties") && !name.contains('/')) {
                sdkMarkerFiles[lower]?.let { sdk ->
                    markers.getOrPut(sdk) { ArrayList() }.add(name)
                }
            }
            if (!name.startsWith("assets/")) continue
            val ext = lower.substringAfterLast('.', "")
            when {
                ext == "html" || ext == "htm" -> if (web.size < maxEach) web.add(name)
                ext == "js" -> if (scripts < 5000) scripts++
                ext in configExt && noisePath.none { lower.contains(it) } ->
                    if (config.size < maxEach) config.add(name)
            }
        }

        return Result(
            webPayloads = web.sorted(),
            scriptCount = scripts,
            configFiles = config.sorted(),
            sdkMarkers = markers.mapValues { it.value.sorted() },
        )
    }
}
