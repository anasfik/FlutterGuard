package com.flutterguard.app.scan

/**
 * Which storage namespace a report describes. A picked/shared APK and the
 * installed app that happens to use the same package name are different
 * subjects and must never be compared.
 */
enum class ScanNamespace { INSTALLED, FILE }

/**
 * What a comparison row talks about. [label] is the noun used in the history
 * log lines (`+ host …`, `- finding …`).
 */
enum class DiffCategory(val label: String) {
    VERSION("version"),
    PERMISSIONS("permission"),
    HOSTS("host"),
    ROUTES("route"),
    PROVIDERS("provider"),
    DEPENDENCIES("dep"),
    NATIVE_LIBS("native lib"),
    FINDINGS("finding"),
    NETWORK_POLICY("network"),
    SIGNING("signing"),
}

/** Direction of one difference, independent of ordering. */
enum class DiffChange { ADDED, REMOVED, CHANGED }

/**
 * One difference between two reports.
 *
 * [identity] is safe by construction: for a finding it is the rule id plus
 * scrubbed source provenance, never an evidence value, snippet or hash of one.
 * [detail] carries only safe facts (severity/kind transitions, fingerprint
 * prefixes that are already public). [occurrences] counts indistinguishable
 * duplicates that were coalesced into this one row, so nothing is silently
 * deduplicated.
 */
data class ReportChange(
    val category: DiffCategory,
    val change: DiffChange,
    val identity: String,
    val detail: String? = null,
    val occurrences: Int = 1,
)

/** Why two reports can or cannot be compared. */
enum class ComparisonStatus { COMPARED, PACKAGE_MISMATCH, NAMESPACE_MISMATCH }

/** One side's subject identity, recorded even when the comparison is rejected. */
data class ReportIdentity(
    val packageName: String,
    val versionName: String?,
    val versionCode: Long,
    val namespace: ScanNamespace,
) {
    /** `1.0.0 (1)`; an unrecovered version name stays unknown, never guessed. */
    val versionLabel: String get() = "${versionName ?: "?"} ($versionCode)"
}

/**
 * Structured, deterministic difference between two completed audits.
 *
 * A rejected comparison ([status] != [COMPARED]) never carries changes: an
 * unrelated package or namespace must not produce a plausible-looking diff.
 * [unavailable] lists categories the historical side did not record (old
 * snapshots); those are skipped, never reported as removals.
 */
data class ReportComparison(
    val status: ComparisonStatus,
    val before: ReportIdentity,
    val after: ReportIdentity,
    val changes: List<ReportChange> = emptyList(),
    val unavailable: Set<DiffCategory> = emptySet(),
    /** Duplicate occurrences coalesced across all rows (sum of `occurrences - 1`). */
    val coalesced: Int = 0,
) {
    val rejected: Boolean get() = status != ComparisonStatus.COMPARED

    val rejectedReason: String?
        get() = when (status) {
            ComparisonStatus.COMPARED -> null
            ComparisonStatus.PACKAGE_MISMATCH ->
                "Not compared: different packages (${before.packageName} vs ${after.packageName})."
            ComparisonStatus.NAMESPACE_MISMATCH ->
                "Not compared: one report is an installed app and the other a picked APK file" +
                    " (${before.packageName}). They are different subjects even with the same package name."
        }

    /** True only when both sides recorded a genuinely different version. */
    val versionChanged: Boolean get() = !rejected && before.versionLabel != after.versionLabel

    val added: Int get() = changes.count { it.change == DiffChange.ADDED }
    val removed: Int get() = changes.count { it.change == DiffChange.REMOVED }
    val modified: Int get() = changes.count { it.change == DiffChange.CHANGED }
}

/** One value in a category, with the safe facts a change may report. */
internal data class DiffFact(
    val detail: String? = null,
    val severity: Severity? = null,
    val kind: FindingKind? = null,
    val occurrences: Int = 1,
)

/** Normalized facts of one side; a category absent from [categories] is not compared. */
internal data class DiffFacts(
    val categories: Map<DiffCategory, Map<String, DiffFact>>,
    val unavailable: Set<DiffCategory> = emptySet(),
)

/** Deterministic ordering shared by every comparison consumer. */
internal val CHANGE_ORDER: Comparator<ReportChange> = compareBy(
    { it.category.ordinal },
    { it.change.ordinal },
    { it.identity },
    { it.detail ?: "" },
)

/**
 * Pure comparison core: no I/O, no Android, no secret access. Callers pass
 * facts that were already scrubbed against the reports' privately retained
 * secret values, so this object cannot serialize a raw value by accident.
 */
internal object DiffEngine {

    fun compare(
        before: DiffFacts,
        after: DiffFacts,
        unavailable: Set<DiffCategory> = emptySet(),
    ): List<ReportChange> {
        val skipped = before.unavailable + after.unavailable + unavailable
        val out = ArrayList<ReportChange>()
        for (category in DiffCategory.entries) {
            if (category == DiffCategory.VERSION) continue
            if (category in skipped) continue
            val old = before.categories[category].orEmpty()
            val new = after.categories[category].orEmpty()
            for ((key, fact) in old) {
                if (key !in new) out += ReportChange(category, DiffChange.REMOVED, key, removedDetail(category, fact), fact.occurrences)
            }
            for ((key, fact) in new) {
                val previous = old[key]
                if (previous == null) {
                    out += ReportChange(category, DiffChange.ADDED, key, addedDetail(category, fact), fact.occurrences)
                } else {
                    val detail = differences(category, previous, fact) ?: continue
                    out += ReportChange(
                        category,
                        DiffChange.CHANGED,
                        key,
                        detail,
                        maxOf(previous.occurrences, fact.occurrences),
                    )
                }
            }
        }
        return out.sortedWith(CHANGE_ORDER)
    }

    private fun addedDetail(category: DiffCategory, fact: DiffFact): String? =
        when {
            category == DiffCategory.NATIVE_LIBS && fact.detail != null -> "sha256 ${fact.detail}"
            else -> fact.detail
        }

    private fun removedDetail(category: DiffCategory, fact: DiffFact): String? = addedDetail(category, fact)

    private fun differences(category: DiffCategory, old: DiffFact, new: DiffFact): String? {
        val parts = ArrayList<String>(3)
        if (old.severity != null && new.severity != null && old.severity != new.severity) {
            parts += "severity ${old.severity} → ${new.severity}"
        }
        if (old.kind != null && new.kind != null && old.kind != new.kind) {
            parts += "kind ${old.kind} → ${new.kind}"
        }
        if (old.detail != null && new.detail != null && old.detail != new.detail) {
            parts += if (category == DiffCategory.NATIVE_LIBS) {
                "sha256 ${old.detail} → ${new.detail}"
            } else {
                "${old.detail} → ${new.detail}"
            }
        }
        return parts.takeIf { it.isNotEmpty() }?.joinToString("; ")
    }
}

/**
 * Compare two completed reports: what the update changed in the artifact.
 *
 * Only sorted, deduplicated facts leave this object — rule identity plus safe
 * provenance, severity, kind, host/route/dependency/provider/permission
 * strings, native library names and signing certificate fingerprints. Raw
 * evidence values, snippets and hashes of secrets are never part of a
 * comparison. Findings are coalesced per (rule id, scrubbed source) and the
 * duplicate count is reported. A candidate string stays a candidate: a diff is
 * artifact evidence, not introduced or fixed exploitability.
 */
object ReportDiff {

    fun compare(before: Report, after: Report): ReportComparison {
        val beforeId = identity(before)
        val afterId = identity(after)
        if (beforeId.packageName != afterId.packageName) {
            return ReportComparison(ComparisonStatus.PACKAGE_MISMATCH, beforeId, afterId)
        }
        if (beforeId.namespace != afterId.namespace) {
            return ReportComparison(ComparisonStatus.NAMESPACE_MISMATCH, beforeId, afterId)
        }

        val secrets = (before.secretValues() + after.secretValues()).distinct()
        val scrub = Evidence.prepared(secrets)
        val oldFacts = reportFacts(before, scrub)
        val newFacts = reportFacts(after, scrub)
        val unavailable = oldFacts.unavailable + newFacts.unavailable

        val changes = ArrayList<ReportChange>()
        if (beforeId.versionLabel != afterId.versionLabel) {
            changes += ReportChange(
                DiffCategory.VERSION,
                DiffChange.CHANGED,
                "${beforeId.versionLabel} → ${afterId.versionLabel}",
            )
        }
        changes += DiffEngine.compare(oldFacts, newFacts, unavailable)
        return ReportComparison(
            status = ComparisonStatus.COMPARED,
            before = beforeId,
            after = afterId,
            changes = changes.sortedWith(CHANGE_ORDER),
            unavailable = unavailable,
            coalesced = changes.sumOf { (it.occurrences - 1).coerceAtLeast(0) },
        )
    }

    /** Subject identity of one report, including its storage namespace. */
    fun identity(report: Report): ReportIdentity = ReportIdentity(
        packageName = report.meta.packageName,
        versionName = report.meta.versionName,
        versionCode = report.meta.versionCode,
        namespace = if (report.meta.fileScan) ScanNamespace.FILE else ScanNamespace.INSTALLED,
    )

    /**
     * Facts for one live report. Every category is available because a live
     * report always knows its own inventory; only a signing certificate is
     * reported unavailable when it was never recovered.
     */
    internal fun reportFacts(report: Report, scrub: (String) -> String): DiffFacts {
        val categories = LinkedHashMap<DiffCategory, Map<String, DiffFact>>()
        categories[DiffCategory.PERMISSIONS] =
            report.permissions.map { scrub(it.name) }.distinct().sorted().associateWith { DiffFact() }
        categories[DiffCategory.HOSTS] =
            report.hosts.map { scrub(it.host) }.distinct().sorted().associateWith { DiffFact() }
        categories[DiffCategory.ROUTES] =
            report.routes.map(scrub).distinct().sorted().associateWith { DiffFact() }
        categories[DiffCategory.PROVIDERS] =
            report.thirdParty.map { scrub(it.service) }.distinct().sorted().associateWith { DiffFact() }
        categories[DiffCategory.DEPENDENCIES] =
            report.framework.dartDeps.map(scrub).distinct().sorted().associateWith { DiffFact() }
        categories[DiffCategory.NATIVE_LIBS] = report.meta.nativeLibs
            .groupBy { "${it.abi}/${it.name}" }
            .mapValues { (_, libs) -> DiffFact(detail = libs.mapNotNull { it.sha256 }.minOrNull()) }
            .toSortedMap()
        categories[DiffCategory.FINDINGS] = findingFacts(report.findings, scrub, networkOnly = false)
        categories[DiffCategory.NETWORK_POLICY] = findingFacts(report.findings, scrub, networkOnly = true)

        val unavailable = HashSet<DiffCategory>()
        val fingerprint = report.signing.sha256Fingerprint
        if (fingerprint == null) {
            unavailable += DiffCategory.SIGNING
        } else {
            categories[DiffCategory.SIGNING] = mapOf("certificate" to DiffFact(detail = fingerprint))
        }
        return DiffFacts(categories, unavailable)
    }

    /**
     * One fact per (rule id, safe source). Indistinguishable duplicates are
     * coalesced into [DiffFact.occurrences]; the most severe severity and the
     * least certain kind win so a coalesced row never looks cleaner than its
     * parts.
     */
    private fun findingFacts(
        findings: List<Finding>,
        scrub: (String) -> String,
        networkOnly: Boolean,
    ): Map<String, DiffFact> {
        val out = HashMap<String, DiffFact>()
        for (finding in findings) {
            val isNetwork = finding.id.startsWith("NET-")
            if (isNetwork != networkOnly) continue
            val sources = finding.evidence
                .map { scrub(it.source.ifBlank { "artifact" }) }
                .ifEmpty { listOf("artifact") }
            for (source in sources) {
                val key = "${finding.id} @ $source"
                val existing = out[key]
                out[key] = DiffFact(
                    severity = listOfNotNull(existing?.severity, finding.severity).minByOrNull { it.ordinal },
                    kind = existing?.kind?.let { FindingKind.lessCertain(it, finding.kind) } ?: finding.kind,
                    occurrences = (existing?.occurrences ?: 0) + 1,
                )
            }
        }
        return out.toSortedMap()
    }
}
