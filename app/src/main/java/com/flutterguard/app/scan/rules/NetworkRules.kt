package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.Severity
import com.flutterguard.app.scan.parsers.AxmlNode

/** Network security checks: cleartext, NSC semantics, trust + pinning signals. */
object NetworkRules {

    fun evaluate(
        nsc: AxmlNode?,                 // decoded res/xml/network_security_config*.xml (root node), if any
        cleartextFlag: Boolean?,
        targetSdk: Int?,
        httpHosts: Set<String>,
        nscDeclared: Boolean = false,   // manifest references a config we could not decode
    ): List<Finding> {
        val findings = ArrayList<Finding>()
        if (nsc == null && nscDeclared) {
            return listOf(
                f(
                    "NET-NSC-UNRESOLVED", "Network security config not decoded",
                    "AndroidManifest declares android:networkSecurityConfig, but the referenced res/xml document could not be " +
                        "parsed as a network-security-config root. Cleartext and pinning policy are therefore unknown from the artifact.",
                    Severity.INFO,
                    "Inspect res/xml manually; keep the config declarative and root element stable.",
                ),
            )
        }
        if (nsc == null) {
            // cleartextFlag is already reported by MAN-CLEARTEXT; only the SDK default is new here.
            val defaultCleartext = (targetSdk ?: 30) < 28
            if (defaultCleartext) {
                findings += f(
                    "NET-CLEARTEXT-DEFAULT", "No network security config",
                    "The app ships no networkSecurityConfig and targets SDK ${targetSdk ?: "?"}, where cleartext HTTP is permitted by default. HTTP can be intercepted on-path.",
                    Severity.MEDIUM,
                    "Add res/xml/network_security_config.xml with cleartextTrafficPermitted=false and explicit pins.",
                )
            }
            return findings
        }

        val base = nsc.child("base-config")
        val baseCleartext = base?.bool("cleartextTrafficPermitted") == true
        val dcCleartext = nsc.children("domain-config").filter { it.bool("cleartextTrafficPermitted") == true }
        val cleartextDomains = dcCleartext.flatMap { it.children("domain") }.mapNotNull { it.attr("value") ?: it.text }
        val loopbackOnly = cleartextDomains.isNotEmpty() && cleartextDomains.all {
            it == "127.0.0.1" || it == "::1" || it.equals("localhost", true)
        }
        if (baseCleartext) {
            findings += f(
                "NET-CLEARTEXT", "NSC permits cleartext traffic",
                "cleartextTrafficPermitted=true in base-config, so every host the app contacts may be reached over plain HTTP.",
                Severity.HIGH, "Restrict cleartext to the specific dev hosts, never base-config.",
            )
        } else if (dcCleartext.isNotEmpty()) {
            findings += f(
                "NET-CLEARTEXT", "NSC permits cleartext traffic",
                "cleartextTrafficPermitted=true for: ${cleartextDomains.joinToString().ifEmpty { "domain-config without <domain>" }}.",
                if (loopbackOnly) Severity.INFO else Severity.HIGH,
                if (loopbackOnly) "Loopback-only cleartext is expected for an embedded server; keep it off real hosts."
                else "Restrict cleartext to the specific dev hosts, never production endpoints.",
            )
        }

        val trustDebug = nsc.child("debug-overrides") != null
        if (trustDebug) findings += f(
            "NET-DEBUG-OVERRIDES", "debug-overrides shipped in release artifact",
            "The NSC contains <debug-overrides>; on debuggable builds extra trust anchors apply — verify this file is the release variant.",
            Severity.LOW, "Strip debug-overrides from release NSC files.", "MASVS-NETWORK-1",
        )

        val configs: List<AxmlNode> = ArrayList<AxmlNode>().apply {
            base?.let { add(it) }
            addAll(nsc.children("domain-config"))
            if (isEmpty()) add(nsc)
        }

        // trust anchors: user-installed CAs
        val userAnchors = ArrayList<String>()
        for (dc in configs) {
            val covered = dc.children("domain").mapNotNull { it.attr("value") ?: it.text }
            for (ta in dc.children("trust-anchors")) {
                for (c in ta.children("certificates")) {
                    if (c.attr("src") == "user") {
                        val scope = when {
                            dc.name == "base-config" || dc === nsc -> "* (all hosts)"
                            covered.isNotEmpty() -> covered.joinToString()
                            else -> "?"
                        }
                        userAnchors.add(scope)
                    }
                }
            }
        }
        if (userAnchors.isNotEmpty()) findings += f(
            "NET-USERCA", "App trusts user-installed CAs",
            "trust-anchors include src=\"user\" (${userAnchors.joinToString()}). Traffic can be intercepted with a proxy using a user CA on a non-rooted device.",
            Severity.HIGH, "Trust only system anchors in release; use debug-overrides for local proxying.",
            "MASVS-NETWORK-2",
        )

        // pin-set
        for (dc in configs) {
            val pinSet = dc.child("pin-set") ?: continue
            val pins = pinSet.children("pin")
            val sha1Only = pins.isNotEmpty() && pins.all { (it.attr("digest") ?: "SHA-256") == "SHA-1" }
            val expiry = pinSet.attr("expiration")
            val covered = dc.children("domain").mapNotNull { it.attr("value") }.joinToString().ifEmpty { "base (all)" }
            findings += f(
                "NET-PINS", "Certificate pinning configured (${pins.size} pin(s))",
                "pin-set found covering $covered." +
                    (if (sha1Only) " Pins use SHA-1 digests (weak)." else "") +
                    (if (expiry != null) " Expiration: $expiry (after expiry the app falls back to standard CA validation)." else "") +
                    " Note: this pins the Java layer only — Flutter/Dart traffic (libapp.so) bypasses the Android NSC unless the app also pins inside Dart.",
                if (sha1Only) Severity.MEDIUM else Severity.INFO,
                "Pin with SHA-256, include a backup pin, and pin in the Dart layer too.",
                "MASVS-NETWORK-2",
            )
        }

        if (httpHosts.isNotEmpty()) findings += f(
            "NET-HTTP-HOSTS", "Plain-HTTP endpoints referenced (${httpHosts.size})",
            "http:// URLs found pointing at: ${httpHosts.take(8).joinToString()}${if (httpHosts.size > 8) " …" else ""}",
            Severity.MEDIUM, "Serve every endpoint over HTTPS.", "MASVS-NETWORK-1",
        )
        return findings
    }

    private fun f(id: String, t: String, d: String, s: Severity, r: String, m: String = "MASVS-NETWORK-1") =
        Finding(id, t, s, d, emptyList(), r, listOf(m))
}
