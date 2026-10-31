package com.flutterguard.app.scan.rules

import android.content.Context
import android.content.pm.PackageManager
import com.flutterguard.app.scan.parsers.AxmlNode
import com.flutterguard.app.scan.DeepLink
import com.flutterguard.app.scan.Evidence
import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.PermissionHit
import com.flutterguard.app.scan.Severity
/** Manifest-centric checks: components, permissions, flags, deep links. */
object ManifestRules {

    private val riskyPermissions = mapOf(
        "android.permission.SYSTEM_ALERT_WINDOW" to "Draw over other apps (overlay attacks / tapjacking)",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "Can sideload other APKs",
        "android.permission.PACKAGE_USAGE_STATS" to "Reads device usage history",
        "android.permission.QUERY_ALL_PACKAGES" to "Enumerates every installed app",
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to "Accessibility access (screen reading / input injection)",
        "android.permission.READ_SMS" to "Reads SMS messages (OTP interception)",
        "android.permission.RECEIVE_SMS" to "Receives SMS (OTP interception)",
        "android.permission.READ_CALL_LOG" to "Reads call history",
        "android.permission.RECORD_AUDIO" to "Microphone access",
        "android.permission.CAMERA" to "Camera access",
        "android.permission.ACCESS_FINE_LOCATION" to "Precise location",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "Location while app is not in use",
        "android.permission.READ_CONTACTS" to "Reads contacts",
        "android.permission.MANAGE_EXTERNAL_STORAGE" to "All-files access",
        "android.permission.BIND_DEVICE_ADMIN" to "Device administrator",
    )

    private fun String.toSdkInt(): Int? =
        if (startsWith("0x", ignoreCase = true)) substring(2).toIntOrNull(16) else toIntOrNull()

    private val oauthishSchemes = listOf("oauth", "login", "auth", "callback", "token", " redirect")

    fun evaluate(
        context: Context,
        manifest: AxmlNode,
        targetSdk: Int?,
    ): Pair<List<Finding>, ManifestFacts> {
        val findings = ArrayList<Finding>()
        val facts = ManifestFacts()
        val customSchemes = LinkedHashMap<String, MutableList<String>>()
        val customSchemeRisky = LinkedHashSet<String>()

        val usesSdk = manifest.child("uses-sdk")
        facts.minSdkAttr = usesSdk?.attr("minSdkVersion")?.toSdkInt()
        facts.targetSdkAttr = usesSdk?.attr("targetSdkVersion")?.toSdkInt()
        val appNode = manifest.child("application")

        // --- application-level flags ---
        if (appNode?.bool("debuggable") == true) findings += finding(
            "MAN-DEBUG", "App is debuggable",
            "android:debuggable=true in the manifest. Any adb-connected host can debug it, read its heap and invoke methods.",
            Severity.HIGH, "Ship release builds without android:debuggable.", "MASVS-RESILIENCE-1",
        )
        if (appNode?.bool("testOnly") == true) findings += finding(
            "MAN-TESTONLY", "Test-only build installed",
            "android:testOnly is set — this artifact was installed via IDE/studio and never meant for distribution.",
            Severity.MEDIUM, "Do not distribute test-only builds.", "MASVS-CONFIG",
        )

        val allowBackup = appNode?.bool("allowBackup")
        val hasBackupRules = appNode?.attr("dataExtractionRules") != null || appNode?.attr("fullBackupContent") != null
        if (allowBackup != false) findings += finding(
            "MAN-BACKUP", "Application data included in cloud/adb backups",
            "allowBackup is not explicitly false" +
                (if (hasBackupRules) " (backup rules present — review their exclusions)" else " and no dataExtractionRules/fullBackupContent rules were found") +
                ". Sensitive data in the sandbox can leave the device via backups.",
            if (hasBackupRules) Severity.LOW else Severity.MEDIUM,
            "Set android:allowBackup=false, or add dataExtractionRules excluding prefs/databases with tokens.",
            "MASVS-STORAGE-1",
        )

        val cleartextFlag = appNode?.bool("usesCleartextTraffic")
        facts.usesCleartextTraffic = cleartextFlag
        val nscRef = appNode?.attr("networkSecurityConfig")
        if (cleartextFlag == true) findings += finding(
            "MAN-CLEARTEXT", "Cleartext traffic allowed app-wide",
            if (nscRef != null)
                "android:usesCleartextTraffic=true while a network security config is also declared — the attribute is the " +
                    "app-wide default and the config can only narrow it, so any host it does not cover stays plaintext."
            else
                "android:usesCleartextTraffic=true — HTTP is permitted for every host, with no network security config to narrow it.",
            if (nscRef != null) Severity.MEDIUM else Severity.HIGH,
            "Remove the flag and use HTTPS everywhere; constrain exceptions in a network security config.",
            "MASVS-NETWORK-1",
        )
        facts.networkSecurityConfigRef = nscRef

        if (manifest.attr("sharedUserId") != null) findings += finding(
            "MAN-SHAREDUID", "Legacy sharedUserId declared",
            "sharedUserId couples this app's data to other apps signed with the same key.",
            Severity.LOW, "Remove sharedUserId (deprecated since API 29).", "MASVS-PLATFORM-2",
        )

        // --- permissions (manifest level) ---
        val pm = context.packageManager
        for (node in manifest.children("uses-permission").plus(manifest.children("permission"))) {
            val name = node.attr("name") ?: continue
            if (node.name == "uses-permission") facts.requestedPermissions.add(name)
            val protection = try {
                val pi = pm.getPermissionInfo(name, 0)
                // Read the field, not `getProtection()`. The getter only exists from
                // API 28 and minSdk is 26, so on Android 8.0/8.1 it throws
                // NoSuchMethodError — an Error, which the catch below does not cover.
                @Suppress("DEPRECATION")
                val level = pi.protectionLevel
                when (level and 0xF) {
                    2 -> if (level and 0x10 != 0) "signature|privileged" else "signature"
                    3 -> "dangerous"
                    4 -> "normal"
                    else -> "protection=0x${level.toString(16)}"
                }
            } catch (_: Exception) {
                "custom/unknown"
            }
            facts.permissionHits.add(
                PermissionHit(name, protection, riskyPermissions[name] ?: "")
            )
            if (node.name == "permission" && node.attr("protectionLevel") == "dangerous") findings += finding(
                "MAN-CUSTOMPERM", "Custom permission with dangerous protectionLevel",
                "$name is declared dangerous — any app requesting it gets broad access without signature check.",
                Severity.MEDIUM, "Use signature protectionLevel for custom permissions.", "MASVS-PLATFORM-2",
            )
        }

        // --- components (application level) + deep links ---
        if (appNode == null) return findings to facts
        val componentTags = listOf("activity", "activity-alias", "service", "receiver", "provider")
        for (tag in componentTags) {
            for (comp in appNode.children(tag)) {
                val name = comp.attr("name") ?: "(anonymous)"
                val short = name.substringAfterLast('.')
                val exportedAttr = comp.bool("exported")
                val hasFilter = comp.children("intent-filter").isNotEmpty()
                val exported = exportedAttr == true || (exportedAttr == null && hasFilter && (targetSdk ?: facts.targetSdkAttr ?: 30) < 31)
                val permission = comp.attr("permission")
                if (exported && tag != "activity-alias") {
                    // A guard permission makes the component unreachable for
                    // ordinary apps; signature-level guards are not exposure.
                    val sev = when {
                        permission != null -> Severity.LOW
                        tag == "provider" -> Severity.HIGH
                        tag == "service" -> Severity.HIGH
                        tag == "receiver" -> Severity.MEDIUM
                        else -> Severity.LOW
                    }
                    val why = when (tag) {
                        "provider" -> "Any app can query this ContentProvider; check grantUriPermissions/path-permission coverage."
                        "service" -> "Any app can start/bind this service (IPC surface)."
                        "receiver" -> "Any app can broadcast to this receiver (spoofing/piggybacking)."
                        else -> "Exported activity — launchable by any app."
                    }
                    findings += finding(
                        "MAN-EXPORTED-$tag", "Exported $tag: $short",
                        "$why ${if (permission != null) "Guarded by permission $permission." else "No permission guard."}",
                        sev, "Export only what needs exposing; guard with signature-level permissions.",
                        "MASVS-PLATFORM-2",
                    )
                }
                if (tag == "provider") {
                    val grant = comp.bool("grantUriPermissions")
                    if (grant == true) facts.providersGrantUri.add(short)
                }
                for (f in comp.children("intent-filter")) {
                    val autoVerify = f.bool("autoVerify") == true
                    val actions = f.children("action").mapNotNull { it.attr("name") }
                    val browsable = f.children("category").any { it.attr("name") == "android.intent.category.BROWSABLE" }
                    val isView = actions.any { it.endsWith("VIEW") }
                    for (d in f.children("data")) {
                        val scheme = d.attr("scheme") ?: continue
                        val host = d.attr("host")
                        if (isView && browsable) facts.deepLinks.add(DeepLink(short, scheme, host, autoVerify))
                        if (isView && browsable && scheme.startsWith("http").not()) {
                            val risky = oauthishSchemes.any { scheme.contains(it, true) } || host?.contains("oauth") == true
                            // One line per scheme, not per intent-filter: wallets and
                            // messengers ship dozens and would bury every other finding.
                            customSchemes.getOrPut(scheme) { ArrayList() }.add("$short ${host ?: "*"}")
                            if (risky) customSchemeRisky.add(scheme)
                        }
                    }
                }
            }
        }

        // One aggregate finding per scheme set: 58 separate deep-link rows is noise.
        if (customSchemes.isNotEmpty()) {
            val risky = customSchemeRisky.isNotEmpty()
            findings += Finding(
                id = "MAN-DEEPLINK",
                title = "${customSchemes.size} custom-scheme deep link(s)",
                severity = if (risky) Severity.HIGH else Severity.MEDIUM,
                detail = "Custom URI schemes can be registered and triggered by any app or browser tab: " +
                    customSchemes.entries.joinToString(", ") { "${it.key}:// (${it.value.size} filter)" } +
                    (if (risky) ". Schemes in: ${customSchemeRisky.joinToString()} look like auth/callback flows — " +
                        "a malicious app claiming the same scheme can capture the returned token." else "."),
                evidence = customSchemes.entries.take(12).map { Evidence("manifest", 0, "${it.key}:// → ${it.value.take(3).joinToString()}") },
                remediation = "Prefer verified App Links (https + assetlinks.json); pass no tokens via custom schemes.",
                masvs = listOf("MASVS-PLATFORM-2"),
            )
        }
        return findings to facts
    }

    data class ManifestFacts(
        var minSdkAttr: Int? = null,
        var targetSdkAttr: Int? = null,
        var usesCleartextTraffic: Boolean? = null,
        var networkSecurityConfigRef: String? = null,
        val requestedPermissions: MutableList<String> = ArrayList(),
        val permissionHits: MutableList<PermissionHit> = ArrayList(),
        val deepLinks: MutableList<DeepLink> = ArrayList(),
        val providersGrantUri: MutableList<String> = ArrayList(),
    )

    private fun finding(id: String, title: String, detail: String, sev: Severity, rem: String, masvs: String) =
        Finding(id, title, sev, detail, emptyList(), rem, listOf(masvs))
}
