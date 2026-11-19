package com.flutterguard.app.scan

import org.json.JSONArray
import org.json.JSONObject

/**
 * Decodes the JSON written by [ReportExport.toJson] back into a [Report] so a
 * persisted scan survives navigation and process death.
 *
 * Honest limits: the JSON is the redacted export format, so evidence `value`
 * (in-memory only), install/update timestamps and artifact raw names are not
 * present. Artifact names in the file are display-masked; the live APK is still
 * the source for previews. Returns null for a file that is not a FlutterGuard
 * report so the caller can say "unreadable" instead of inventing one.
 */
object ReportJson {

    const val SCHEMA = "flutterguard/report/2"

    /** The only other schema this build still reads: it stored no kinds. */
    const val LEGACY_SCHEMA = "flutterguard/report/1"

    private val acceptedSchemas = setOf(LEGACY_SCHEMA, SCHEMA)

    /**
     * Only the exact schemas this build writes or migrated from may be decoded.
     * A malformed, missing or future schema is refused, never defaulted.
     */
    fun acceptsSchema(value: String?): Boolean = value in acceptedSchemas

    fun decode(text: String): Report? {
        val root = runCatching { JSONObject(text) }.getOrNull() ?: return null
        // A file without our schema (or with a future one) is not a report we know
        // how to read: refuse it instead of inventing severity/partRole/isFlutter.
        if (!acceptsSchema(root.str("schema"))) return null
        val metaJson = root.obj("meta") ?: return null
        val packageName = metaJson.str("packageName")?.takeIf { it.isNotBlank() } ?: return null

        val frameworkJson = root.obj("framework")
        val signingJson = root.obj("signing")
        val statsJson = root.obj("stats")

        val meta = AppMeta(
            packageName = packageName,
            label = metaJson.str("label") ?: packageName,
            versionName = metaJson.str("versionName"),
            versionCode = metaJson.long("versionCode"),
            minSdk = metaJson.intOrNull("minSdk"),
            targetSdk = metaJson.intOrNull("targetSdk"),
            installer = metaJson.str("installer"),
            firstInstallMs = 0,
            lastUpdateMs = 0,
            isSystem = metaJson.bool("isSystem"),
            sizeBytes = metaJson.long("sizeBytes"),
            splitCount = metaJson.intOrNull("splitCount") ?: 0,
            abis = metaJson.array("abis").strings(),
            nativeLibs = metaJson.array("nativeLibs").objects().map { lib ->
                NativeLib(
                    name = lib.str("name") ?: "",
                    abi = lib.str("abi") ?: "",
                    sizeBytes = lib.long("size"),
                    sha256 = lib.str("sha256Prefix"),
                    versionMarkers = lib.array("versionMarkers").strings(),
                )
            },
            baseSha256 = metaJson.str("baseApkSha256") ?: "",
            fileScan = metaJson.bool("fileScan"),
        )

        val framework = FrameworkInfo(
            isFlutter = frameworkJson?.bool("isFlutter") ?: false,
            engineVersion = frameworkJson?.str("engineVersion"),
            dartVersion = frameworkJson?.str("dartVersion"),
            obfuscated = frameworkJson?.boolOrNull("obfuscated"),
            buildMode = frameworkJson?.str("buildMode"),
            otherFrameworks = frameworkJson?.array("otherFrameworks").strings().orEmpty(),
            dartDeps = frameworkJson?.array("dartDeps").strings().orEmpty(),
            kernelBlobBytes = frameworkJson?.longOrNull("kernelBlobBytes"),
            snapshotBytes = frameworkJson?.longOrNull("snapshotBytes"),
            engineDebug = frameworkJson?.bool("engineDebug") ?: false,
            libappMissing = frameworkJson?.bool("libappMissing") ?: false,
            // Optional in the schema: absent means unknown, never a default claim.
            // Only a known SnapshotKind label is a kind; a hand-edited number or
            // unknown string decodes as unknown instead of rendering verbatim.
            snapshotKind = frameworkJson?.str("snapshotKind")
                ?.takeIf { s -> SnapshotKind.entries.any { it.label == s } },
            snapshotHash = frameworkJson?.str("snapshotHash"),
            snapshotFeatures = frameworkJson?.array("snapshotFeatures").strings().orEmpty(),
        )

        val signing = SigningInfo(
            signerSubject = signingJson?.str("signerSubject"),
            signerIssuer = null,
            sha256Fingerprint = signingJson?.str("sha256Fingerprint"),
            debugCert = signingJson?.bool("debugCert") ?: false,
            multipleSigners = false,
            rotationHistory = signingJson?.bool("rotationHistory") ?: false,
            validFrom = null,
            validTo = signingJson?.str("validTo"),
            sigAlgorithm = null,
            schemes = signingJson?.array("schemes").strings().orEmpty(),
            notes = emptyList(),
        )

        val stats = ReportStats(
            critical = statsJson?.intOrNull("critical") ?: 0,
            high = statsJson?.intOrNull("high") ?: 0,
            medium = statsJson?.intOrNull("medium") ?: 0,
            low = statsJson?.intOrNull("low") ?: 0,
            info = statsJson?.intOrNull("info") ?: 0,
            stringsScanned = statsJson?.long("stringsScanned") ?: 0,
            durationMs = statsJson?.long("durationMs") ?: 0,
        )

        val findings = root.array("findings").objects().map { f ->
            val id = f.str("id") ?: ""
            val severity = runCatching { Severity.valueOf(f.str("severity") ?: "") }.getOrDefault(Severity.INFO)
            Finding(
                id = id,
                title = f.str("title") ?: "",
                severity = severity,
                detail = f.str("detail") ?: "",
                evidence = f.array("evidence").objects().map { e ->
                    Evidence(
                        source = e.str("source") ?: "",
                        offset = e.long("offset"),
                        snippet = e.str("snippet") ?: "",
                        value = null, // never persisted in the default export
                    )
                },
                remediation = f.str("remediation") ?: "",
                masvs = f.array("masvs").strings(),
                // Re-derive from the catalog; a serialized kind may only lower
                // confidence, so a tampered file cannot promote an unknown ID.
                kind = FindingKind.parse(f.str("kind"))
                    ?.let { FindingKind.lessCertain(FindingCatalog.kindOf(id, severity), it) }
                    ?: FindingCatalog.kindOf(id, severity),
            )
        }

        return Report(
            meta = meta,
            framework = framework,
            signing = signing,
            findings = findings,
            hosts = root.array("hosts").objects().map { h ->
                HostInfo(
                    host = h.str("host") ?: "",
                    classification = h.str("class") ?: "unclassified",
                    samples = h.array("samples").strings(),
                    appOwned = h.bool("appOwned"),
                )
            },
            channels = root.array("channels").objects().map { c ->
                ChannelInfo(
                    name = c.str("name") ?: "",
                    origin = c.str("origin") ?: "",
                    kind = c.str("kind") ?: "custom",
                )
            },
            thirdParty = root.array("thirdParty").objects().map { t ->
                ThirdPartyHit(service = t.str("service") ?: "", evidence = t.array("evidence").strings())
            },
            permissions = root.array("permissions").objects().map { p ->
                PermissionHit(
                    name = p.str("name") ?: "",
                    protection = p.str("protection") ?: "",
                    description = p.str("note") ?: "",
                )
            },
            deepLinks = root.array("deepLinks").objects().map { d ->
                DeepLink(
                    component = d.str("component") ?: "",
                    scheme = d.str("scheme") ?: "",
                    host = d.str("host")?.takeIf { it.isNotBlank() },
                    autoVerify = d.bool("autoVerify"),
                )
            },
            // Kind counts are recomputed from the decoded findings (schema 1
            // carried none); severity totals stay the stored totals.
            stats = stats.copy(
                confirmed = findings.count { it.kind == FindingKind.CONFIRMED },
                suspected = findings.count { it.kind == FindingKind.SUSPECTED },
                informational = findings.count { it.kind == FindingKind.INFORMATIONAL },
            ),
            // Never trust the stored letter: it was computed from leads too.
            grade = gradeOf(findings),
            routes = root.array("routes").strings(),
            dartSources = root.array("dartSources").strings(),
            artifacts = root.array("artifacts").objects().map { a ->
                ArtifactEntry(
                    partIndex = a.intOrNull("partIndex") ?: 0,
                    partRole = a.str("partRole") ?: "base",
                    // Stored as the masked display name: identity stays in the live APK.
                    name = a.str("name") ?: "",
                    compressedBytes = a.long("compressedBytes"),
                    uncompressedBytes = a.long("uncompressedBytes"),
                    category = runCatching { ArtifactCategory.valueOf(a.str("category") ?: "") }
                        .getOrDefault(ArtifactCategory.OTHER),
                )
            },
            generatedAt = root.longOrNull("generatedAt") ?: 0,
        )
    }

    // ------------------------------------------------------------ json helpers

    private fun JSONObject.str(key: String): String? =
        if (has(key) && !isNull(key)) optString(key).takeIf { it.isNotEmpty() } else null

    private fun JSONObject.long(key: String): Long = if (has(key) && !isNull(key)) optLong(key) else 0L
    private fun JSONObject.longOrNull(key: String): Long? = if (has(key) && !isNull(key)) optLong(key) else null
    private fun JSONObject.intOrNull(key: String): Int? = if (has(key) && !isNull(key)) optInt(key) else null
    private fun JSONObject.bool(key: String): Boolean = has(key) && !isNull(key) && optBoolean(key)
    private fun JSONObject.boolOrNull(key: String): Boolean? = if (has(key) && !isNull(key)) optBoolean(key) else null
    private fun JSONObject.obj(key: String): JSONObject? = optJSONObject(key)
    private fun JSONObject.array(key: String): JSONArray? = optJSONArray(key)

    private fun JSONArray?.strings(): List<String> {
        if (this == null) return emptyList()
        return (0 until length()).mapNotNull { i ->
            if (isNull(i)) null else optString(i).takeIf { it.isNotEmpty() }
        }
    }

    private fun JSONArray?.objects(): List<JSONObject> {
        if (this == null) return emptyList()
        return (0 until length()).mapNotNull { i -> optJSONObject(i) }
    }
}
