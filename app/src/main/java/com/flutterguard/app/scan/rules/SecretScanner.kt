package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.Evidence
import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.HostInfo
import com.flutterguard.app.scan.Provenance
import com.flutterguard.app.scan.Severity
import com.flutterguard.app.scan.parsers.X509

/** Which artifact layer a string came from — cheap gating keeps big apps fast. */
enum class Layer { DEX, SO, ASSET, ARSC, KERNEL }

data class SecretRule(
    val id: String,
    val title: String,
    val severity: Severity,
    val gates: List<String>,          // literal (case-insensitive) pre-filters
    val caseSensitiveGates: List<String> = emptyList(),
    val regex: Regex,
    val remediation: String,
    val masvs: List<String>,
    val group: Int = 1,               // capture group holding the secret
    /** Extra validation for noisy generic rules (raw string, captured value). */
    val accept: ((String, String) -> Boolean)? = null,
    /** false = the matched value is a public identifier by design; its evidence
     *  stays visible verbatim. true (default) = credential; snippet is masked. */
    val secret: Boolean = true,
    /** Honest framing appended to the finding detail (e.g. hypothesis labeling). */
    val note: String? = null,
)

/** File extensions that mark a path as source or build artifact, not an endpoint.
 *  Shared by [SecretScanner] route filtering and the route-tree helper. */
internal val sourcePathExtensions = listOf(
    ".dart", ".rs", ".proto", ".kt", ".java", ".swift", ".cc", ".cpp", ".c", ".h",
    ".go", ".py", ".ts", ".js", ".m", ".mm", ".gradle", ".cmake", ".lock", ".so",
    ".png", ".svg", ".ttf", ".otf",
)

/**
 * Central streaming scanner: every extracted string (DEX pool, .so and Dart
 * kernel printable runs, asset contents, resource values) flows through
 * [feed]; findings, hosts, channels and Dart deps accumulate with bounded
 * memory.
 *
 * @param appTokens tokens derived from the app's own package/label; hosts that
 *   contain one are tagged first-party so SDK/doc noise can be separated from
 *   the endpoints that actually matter.
 */
class SecretScanner(private val appTokens: Set<String> = emptySet()) {

    /** Static string markers are hypotheses: presence in the string pool is not
     *  proof the code path is reachable or exploitable. */
    private val MARKER_HYPOTHESIS =
        " Static marker recovered from strings: a hypothesis about reachable code, not confirmed exploitation."

    val rules: List<SecretRule> = buildRules()

    val findings = ArrayList<Finding>()
    private val seen = HashMap<String, Int>() // ruleId+value -> evidence count
    private val findingAt = HashMap<String, Int>() // ruleId+value -> index in findings

    /** host -> classification (kept for rule modules that only need the map). */
    val hosts: Map<String, String> get() = hostClass
    private val hostClass = LinkedHashMap<String, String>()
    private val hostSamples = HashMap<String, MutableList<String>>()
    private val hostSeen = HashSet<String>()
    val httpHosts = LinkedHashSet<String>()
    val channels = LinkedHashMap<String, Pair<String, String>>() // name -> origin,kind
    val dartDeps = LinkedHashSet<String>()
    val dexMarkers = LinkedHashMap<String, String>() // marker -> description
    /** Dart-layer security-relevant API markers seen in libapp.so / kernel. */
    val dartMarkers = LinkedHashMap<String, String>()
    /** Proxy/VPN URI schemes compiled into the app (vless://, ss://, ...). */
    val proxySchemes = LinkedHashSet<String>()

    /** TLS pin material found in strings, e.g. OkHttp `sha256/<base64>`. */
    val pinMaterial = LinkedHashSet<String>()

    /** DER certificates embedded as base64, rendered as `CN=… O=…`. */
    val x509Certs = LinkedHashSet<String>()

    /** A PEM private key header was found: the worst possible finding. */
    var privateKeyFound = false
    private var pemPending = false
    private val certChunks = StringBuilder()
    /** API-shaped paths seen in the Dart string layer (not pub docs). */
    val routes = LinkedHashSet<String>()
    /** Dart source files referenced by the kernel (debug/JIT builds only). */
    val dartSources = LinkedHashSet<String>()
    var stringsScanned = 0L
        private set
    var kernelStrings = 0L
        private set

    private val urlRegex = Regex("""(?:https?|wss?)://(?:[A-Za-z0-9\-._~%:]+@)?[A-Za-z0-9\-._~]+(?::\d+)?(?:/[^\s"'<>\\]{0,120})?""")

    /** Userinfo (`user:token@`) must never reach a stored host or sample URL. */
    private val userInfoRegex = Regex("""//[^/@\s]+@""")

    /** ponytail: gate scans over huge strings are windowed to 64 KiB — a
     *  credential past that offset in a single string needs a case-sensitive
     *  gate or a direct feed; raising this raises per-string scan cost. */
    private val gateWindow = 64 * 1024

    /** Case-insensitive gate match inside the bounded window; allocation-free. */
    private fun gateHit(raw: String, gate: String): Boolean =
        raw.indexOf(gate, 0, ignoreCase = true) in 0 until gateWindow
    private val channelRegex = Regex("""^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,}/[A-Za-z0-9_.\-]+/?$""")
    private val packageRegex = Regex("""\bpackage:([a-z0-9_]+)/""")

    /** Single-pass prefilter: only these first segments can start a useful route. */
    private val routePrefixes =
        "api|auth|oauth|v[1-9]|admin|users?|account|login|logout|signup|register|password|payments|checkout|" +
            "webhooks?|upload|download|search|health|config|notifications|chat|messages|graphql|me|profile|" +
            // Candidate named-navigation routes (Navigator-style), outside the narrow API prefixes.
            "settings|dashboard|splash|onboarding|welcome|home|main|feed|cart|orders?|products?|items?|" +
            "details?|lists?|screens?|pages?"
    private val routePrefilter = Regex("""/(?:$routePrefixes)/""")
    private val routeRegex = Regex("""/(?:$routePrefixes)/[A-Za-z0-9_\-{}:./]{2,72}""")

    /** Standalone single-segment named routes ("/profile") from Navigator code. */
    private val standaloneRoutes = setOf(
        "home", "login", "auth", "register", "settings", "profile", "dashboard", "splash",
        "onboarding", "welcome", "main", "feed", "cart", "search", "checkout",
    )

    /** Trailing tokens that mark a path as a source file or build artifact, not an endpoint. */
    private val sourceExt = sourcePathExtensions

    /** Last segment values that come from build-time/config strings rather than an API. */
    private val routeJunkTail = setOf("mod", "lib", "build", "main", "index", "src")

    /** Word-salad detector for binary struct dumps: 3+ consecutive capitals. */
    private fun hasUpperRun(s: String): Boolean {
        var run = 0
        for (c in s) {
            if (c.isUpperCase()) { if (++run >= 3) return true } else run = 0
        }
        return false
    }

    private val knownChannels = listOf(
        "flutter/", "plugins.flutter.io/", "dev.flutter/", "io.flutter.",
        "channels.flutter.io/", "flutter.io/",
    )

    /** Dart APIs that weaken TLS. Kept narrow: generic SDK names appear in every app. */
    private val dartMarkerMap = linkedMapOf(
        "badCertificateCallback" to "HttpClient accepts invalid TLS certificates",
        "setTrustedCertificates" to "custom trust store installed at runtime",
    ).mapValues { (_, desc) -> desc + MARKER_HYPOTHESIS }

    /** Proxy schemes only count as a real config when a payload follows. */
    private val proxyRegex = Regex("""\b(vless|vmess|trojan|hysteria2?|tuic|ss|ssr|socks5|wireguard)://[A-Za-z0-9._~+/=-]{2,}""")

    /** OkHttp `CertificatePinner` style pins: sha256/<base64 SPKI hash>. */
    private val pinRegex = Regex("""sha256/[A-Za-z0-9+/]{20,}={0,2}""")

    /** A PEM private key = header plus base64 body; the header alone is an OpenSSL label. */
    private val pemHeaderRegex = Regex("""-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----""")
    private val pemKeyRegex = Regex("""-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\\rn]*[A-Za-z0-9+/=]{64,}""")

    /** Base64 DER certificate body: always starts with the ASN.1 SEQUENCE header. */
    private val certRegex = Regex("""MII[A-Za-z0-9+/]{80,}={0,2}""")

    /** Reverse-DNS prefixes owned by well-known plugins: real channels, not app code. */
    private val pluginChannels = listOf(
        "dev.fluttercommunity.plus/", "plugins.it_nomads.com/", "com.llfbandit.",
        "io.flutter.plugins.", "plugins.flutter.io/", "dev.flutter/", "flutter/",
        "com.baseflow.", "flutter.baseflow.com/", "com.amazonaws.amplify/", "io.flutter.plugins.firebase",
        "com.fluttercandies/", "com.shoutsocial.", "io.material.plugins/", "com.flutter/",
        "com.alexmercerind/", "dev.leanflutter.plugins/", "plugins.flutter.dev/",
        "sentry.java", "sentry.native", "sentry.flutter", "com.dexterous/",
        "xyz.luan/", "com.github.dart_lang/", "es.antonborri.home_widget/",
    )

    /** Module-registry and URL hosts that pass the channel shape but are package coordinates. */
    private val channelNoise = listOf(
        "vnd.", "type.googleapis.com/", "schemas.android.com/", "xmlpull.org/",
        "w3.org/", "purl.org/", "json-schema.org/", "developer.android.com/",
        "apache.org/", "kotlinlang.org/",
        "golang.org/", "google.golang.org/", "gopkg.in/", "gvisor.dev/", "filippo.io/",
        "go4.org/", "lukechampine.com/", "odoca.com/", "pkg.go.dev/", "golang.zx2c4.com/",
        "github.com/", "gitlab.com/", "bitbucket.org/", "npmjs.com/", "pub.dev/",
        "dart.dev/", "mozilla.org/", "ietf.org/", "unicode.org/", "example.com/",
    )

    /**
     * Documentation / SDK / tooling domains that flood every Flutter kernel blob
     * and DEX pool with license URLs. They are not endpoints of the app under
     * audit, so they are dropped before they can bury the real ones.
     */
    private val noiseHosts = listOf(
        "learn.microsoft.com", "docs.microsoft.com", "microsoft.com", "msdn.microsoft.com",
        "fonts.google.com", "fonts.gstatic.com", "flutter.github.io", "github.com",
        "githubusercontent.com", "gitlab.com", "bitbucket.org", "apple.com",
        "apache.org", "youtube.com", "youtu.be", "developer.android.com",
        "cs.android.com", "android.googlesource.com", "source.android.com",
        "material.io", "m3.material.io", "w3.org", "flutter.dev", "api.flutter.dev",
        "pub.dev", "dart.dev", "html.spec.whatwg.org", "rxmarbles.com",
        "wikipedia.org", "tools.ietf.org", "datatracker.ietf.org", "ietf.org",
        "developer.mozilla.org", "mozilla.org", "unicode.org", "example.com",
        "example.org", "reactivex.io", "dartbug.com", "bit.ly", "sqlite.org",
        "gnu.org", "opensource.org", "creativecommons.org", "json-schema.org",
        "json.org", "ecma-international.org", "code.woboq.org", "jsbin.com",
        "dl.acm.org", "purl.org", "ns.adobe.com", "icu-project.org",
        "goo.gl", "gstatic.com", "google.com", "googleapis.com", "stackoverflow.com",
        "kotlinlang.org", "gradle.org", "jetbrains.com", "oracle.com", "sun.com",
        "openssl.org", "curl.se", "iana.org", "rfc-editor.org", "medium.com",
        "npmjs.com", "nodejs.org", "python.org", "rust-lang.org", "golang.org",
        "chromium.org", "webkit.org", "debian.org", "ubuntu.com", "archlinux.org",
    )

    private val saasHosts = mapOf(
        "sentry.io" to "Sentry", "ingest.sentry.io" to "Sentry", "crashlytics.com" to "Firebase Crashlytics",
        "firebaseio.com" to "Firebase", "firebaseinstallations.googleapis.com" to "Firebase",
        "firebasestorage.app" to "Firebase Storage", "app-measurement.com" to "Firebase Analytics",
        "doubleclick.net" to "Google Ads", "googlesyndication.com" to "Google Ads",
        "appsflyer.com" to "AppsFlyer", "adjust.com" to "Adjust", "braze.com" to "Braze",
        "onesignal.com" to "OneSignal", "mixpanel.com" to "Mixpanel", "amplitude.com" to "Amplitude",
        "segment.io" to "Segment", "branch.io" to "Branch", "facebook.com" to "Facebook",
        "revenuecat.com" to "RevenueCat", "supabase.co" to "Supabase", "stripe.com" to "Stripe",
        "amazonaws.com" to "AWS", "cloudfront.net" to "CloudFront", "cloudfunctions.net" to "Firebase Functions",
        "intercom.io" to "Intercom", "zendesk.com" to "Zendesk", "mapbox.com" to "Mapbox",
        "pusher.com" to "Pusher", "ably.io" to "Ably", "algolia.net" to "Algolia",
    )

    private val dexMarkerMap = mapOf(
        "addJavascriptInterface" to "JavaScript ↔ Java bridge is used (enumerate reachable methods)",
        "setAllowFileAccessFromFileURLs" to "WebView allows file:// pages to read other file:// URLs (SOP bypass)",
        "setAllowUniversalAccessFromFileURLs" to "WebView allows file:// pages universal XSS-style access",
        "setWebContentsDebuggingEnabled" to "Remote WebView debugging may be left enabled",
        "setJavaScriptEnabled" to "WebView JavaScript enabled",
        "onReceivedSslError" to "SSL-error handler present (check it does not call proceed())",
        "JavascriptInterface" to "@JavascriptInterface bridge methods present",
        "loadDataWithBaseURL" to "WebView loads content with a base URL",
    ).mapValues { (_, desc) -> desc + MARKER_HYPOTHESIS }

    fun feed(raw: String, prov: Provenance, layer: Layer) {
        if (raw.length < 6) return
        stringsScanned++
        if (layer == Layer.KERNEL) kernelStrings++
        val len = raw.length
        val lower: String? = if (len < 512) raw.lowercase() else null

        // ---- secret rules (gated) ----
        for (r in rules) {
            var gated = false
            if (lower != null) {
                for (g in r.gates) if (lower.contains(g)) { gated = true; break }
            } else {
                // Strings >=512 chars have no lowercase copy: scan for the
                // case-insensitive gates instead of silently skipping them.
                for (g in r.gates) if (gateHit(raw, g)) { gated = true; break }
            }
            if (!gated) {
                for (g in r.caseSensitiveGates) if (raw.contains(g)) { gated = true; break }
            }
            if (!gated) continue
            val m = r.regex.find(raw) ?: continue
            // Rules without capture groups (group = 1 default) must fall back to
            // the whole match instead of throwing on groupValues[1].
            val value = if (r.group in m.groupValues.indices) m.groupValues[r.group].ifEmpty { m.value } else m.value
            if (value.length < 8) continue
            if (r.accept != null && !r.accept.invoke(raw, value)) continue
            record(r, value, prov)
        }

        // ---- URL / host harvest ----
        if (len < 4096 && (lower == null || raw.contains("://"))) {
            for (m in urlRegex.findAll(raw)) {
                val url = m.value
                // Authority = everything up to the path; userinfo is stripped so a
                // credential-shaped userinfo can never masquerade as the host.
                val authority = url.substringAfter("://").substringBefore('/')
                val host = authority.substringAfterLast('@').substringBefore(':')
                if (host.isEmpty() || host.length > 253) continue
                // A real host has a dot (FQDN, IPv4) or is loopback; bare tokens are
                // regex debris from concatenated strings like "https://6".
                if (!host.contains('.') && host != "localhost") continue
                if (!hostSeen.add(host)) {
                    addSample(host, url)
                    continue
                }
                if (isNoise(host) && !isAppOwned(host)) continue
                if (hostSeen.size <= 6000) {
                    hostClass[host] = classify(host, url)
                    addSample(host, url)
                }
            }
        }

        // ---- Flutter platform-channel names ----
        if (len in 6..100 && raw.contains('/') && raw.contains('.') && raw[0] in 'a'..'z') {
            if (!raw.endsWith('.') && !channelNoise.any { raw.startsWith(it) } &&
                channelRegex.matches(raw) && !channels.containsKey(raw) && channels.size < 300
            ) {
                val domain = raw.substringBefore('/')
                val kind = when {
                    appTokens.any { it.length >= 4 && domain.contains(it) } -> "app"
                    pluginChannels.any { raw.startsWith(it) } -> "plugin"
                    knownChannels.any { raw.startsWith(it) } -> "standard"
                    else -> "custom"
                }
                channels[raw] = (prov.source to kind)
            }
        }

        // ---- Dart package: dependencies (any layer: kernel blob or libapp.so) ----
        // The URI usually sits inside a larger printable run, so it is matched
        // anywhere in the string rather than only at the start.
        if (dartDeps.size < 600 && len < 4096 && raw.contains("package:")) {
            for (m in packageRegex.findAll(raw)) {
                val dep = m.groupValues[1]
                if (dep.length > 1) dartDeps.add(dep)
                if (dartDeps.size >= 600) break
            }
        }

        // ---- API route paths (app endpoints, not pub docs) ----
        // Dart string tables are length-prefixed, so a route is usually embedded
        // inside a longer printable run rather than standing alone.
        // AOT release builds keep the same tables inside libapp.so, so both
        // layers feed routes / Dart source paths; debug builds only add kernel.
        if ((layer == Layer.KERNEL || layer == Layer.SO) && len < 1024 &&
            (routes.size < 60 || dartSources.size < 60)
        ) {
            if (routePrefilter.containsMatchIn(raw)) {
                for (m in routeRegex.findAll(raw)) {
                    val route = m.value.trimEnd('.', ',', ')', '"', '\'', ';')
                    if (route.length !in 6..80) continue
                    // AOT string tables concatenate neighbours, so ".dart" often has junk after it.
                    val dartAt = route.indexOf(".dart")
                    if (dartAt > 0) {
                        val src = route.substring(0, dartAt + 5)
                        if (dartSources.size < 60 && !src.startsWith("/api/lib/")) dartSources.add(src)
                        continue
                    }
                    if (route.substringAfterLast('/') in routeJunkTail) continue
                    if (route.lowercase().let { l -> sourceExt.any { l.endsWith(it) } }) continue
                    // Binary struct dumps and grpc dumps look like paths but have word-salad segments.
                    if (route.split('/').any { it.length > 32 || hasUpperRun(it) }) continue
                    if (routes.size < 60 && !route.startsWith("/api/lib/") && !route.contains("/bus")) routes.add(route)
                }
            }
            // Standalone single-segment named routes ("/profile") from Navigator code.
            if (routes.size < 60 && raw.startsWith("/")) {
                val t = raw.trim()
                if (t.length in 2..40 && t.indexOf('/', 1) < 0 && t.substring(1) in standaloneRoutes) routes.add(t)
            }
        }

        // ---- WebView / bridge markers in DEX ----
        if (layer == Layer.DEX && len < 64) {
            for ((marker, desc) in dexMarkerMap) {
                if (raw == marker) {
                    if (!dexMarkers.containsKey(marker)) dexMarkers[marker] = desc
                }
            }
        }

        // ---- Dart-layer TLS / proxy surface ----
        if (layer == Layer.SO || layer == Layer.KERNEL) {
            if (len < 4096 && dartMarkers.size < 8) {
                for ((marker, desc) in dartMarkerMap) {
                    if (raw.contains(marker)) dartMarkers.putIfAbsent(marker, desc)
                }
            }
            if (len < 4096 && proxySchemes.size < 8) {
                for (m in proxyRegex.findAll(raw)) proxySchemes.add(m.groupValues[1])
            }
            if (len < 4096 && pinMaterial.size < 5) {
                for (m in pinRegex.findAll(raw)) pinMaterial.add(m.value.take(24) + "…")
            }
        }

        // ---- embedded key material ----
        if (!privateKeyFound) {
            when {
                pemKeyRegex.containsMatchIn(raw) -> privateKeyFound = true
                pemHeaderRegex.containsMatchIn(raw) -> pemPending = true
                pemPending && raw.length >= 64 && raw.any { it.isLowerCase() } &&
                    raw.all { it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' } -> {
                    privateKeyFound = true
                    pemPending = false
                }
                // A header only counts when its body follows immediately; anything
                // else (OpenSSL parser labels, hex test vectors) must clear it.
                else -> pemPending = false
            }
        }
        if (len in 300..20000 && raw.contains("MII") && x509Certs.size < 6) {
            for (m in certRegex.findAll(raw)) {
                if (x509Certs.size >= 6) break
                val subject = X509.subject(m.value) ?: continue
                if (subject.length >= 4) x509Certs.add(subject)
            }
        }
        // PEM bodies are stored 64 chars per line, so a certificate arrives as a
        // run of short base64 strings; reassemble until the DER parses.
        val b64ish = raw.length in 16..400 && raw.all { it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' }
        if (b64ish && (certChunks.isNotEmpty() || raw.startsWith("MII"))) {
            certChunks.append(raw)
            if (certChunks.length <= 12_000) {
                val subject = X509.subject(certChunks.toString())
                if (subject != null && subject.length >= 4 && x509Certs.size < 6) {
                    x509Certs.add(subject)
                    certChunks.setLength(0)
                }
            } else certChunks.setLength(0)
        } else if (certChunks.isNotEmpty()) {
            certChunks.setLength(0)
        }
    }

    private fun addSample(host: String, url: String) {
        val l = hostSamples[host] ?: ArrayList<String>(3).also { hostSamples[host] = it }
        if (l.size >= 3 || l.contains(url)) return
        val safeUrl = url.replace(userInfoRegex, "//")
        l.add(if (safeUrl.contains('?')) safeUrl.substringBefore('?') + "?…" else safeUrl.take(120))
    }

    private fun isNoise(host: String): Boolean {
        val h = host.lowercase()
        return noiseHosts.any { h == it || h.endsWith(".$it") }
    }

    fun isAppOwned(host: String): Boolean {
        if (appTokens.isEmpty()) return false
        val labels = host.lowercase().split('.', '-', '_')
        return labels.any { lab -> lab.length >= 4 && appTokens.contains(lab) }
    }

    private fun classify(host: String, url: String): String {
        val h = host.lowercase()
        if (h.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) return "ip-literal"
        for ((suffix, name) in saasHosts) if (h == suffix || h.endsWith(".$suffix")) return "saas:$name"
        if (Regex("""(staging|stage|dev|qa|test|preprod|sandbox|internal)[.\-]""").containsMatchIn(h) ||
            url.contains(Regex("""(?i)//(dev|qa|test|staging|preprod)/"""))
        ) return "staging"
        if (h.endsWith(".local") || h.endsWith(".internal") || h == "localhost") return "internal"
        if (isAppOwned(h)) return "first-party"
        return "unclassified"
    }

    /** Endpoint list ordered: first-party → staging → saas → rest, each by sample count. */
    fun hostInfos(): List<HostInfo> {
        val rank = mapOf("first-party" to 0, "staging" to 1, "internal" to 2)
        return hostClass.map { (h, c) ->
            HostInfo(h, c, hostSamples[h]?.toList() ?: emptyList(), isAppOwned(h))
        }.sortedWith(
            compareBy<HostInfo> { rank[it.classification] ?: if (it.classification.startsWith("saas:")) 3 else 4 }
                .thenByDescending { it.samples.size }
                .thenBy { it.host }
        )
    }

    private fun record(r: SecretRule, value: String, prov: Provenance) {
        val key = r.id + "|" + value
        val prior = seen[key]
        // Dedup is keyed on the raw value, never on the (now masked) snippet.
        if (prior != null) {
            if (prior >= 3) return // cap evidence per unique secret
            seen[key] = prior + 1
            val idx = findingAt[key] ?: return
            val f = findings[idx]
            findings[idx] = f.copy(evidence = f.evidence + evidenceFor(r, value, prov))
            return
        }
        seen[key] = 1
        findingAt[key] = findings.size
        findings.add(
            Finding(
                id = r.id,
                title = r.title,
                severity = r.severity,
                detail = "Value found in ${prov.source}. Pattern: ${r.id}." + (r.note?.let { " $it" } ?: ""),
                evidence = listOf(evidenceFor(r, value, prov)),
                remediation = r.remediation,
                masvs = r.masvs,
            ),
        )
    }

    /** Sensitive rules mask the value by construction; public identifiers stay visible. */
    private fun evidenceFor(r: SecretRule, value: String, prov: Provenance): Evidence =
        Evidence(prov.source, prov.offset, if (r.secret) Evidence.mask(value) else value, value)

    private fun buildRules(): List<SecretRule> = listOf(
        SecretRule(
            "SEC-KEY-PRIVATE", "Hardcoded private key material", Severity.CRITICAL,
            gates = listOf("begin "), caseSensitiveGates = listOf("-----BEGIN"),
            // The bare preamble is a PEM parser label baked into OpenSSL, not a
            // key: a real key has a base64 body right after the header.
            regex = Regex(
                """-----BEGIN ((EC|PGP|OpenSSH|RSA|DSA|ENCRYPTED)? ?PRIVATE KEY( BLOCK)?)-----[\s\\rn]*[A-Za-z0-9+/=]{64,}""",
            ),
            group = 0,
            remediation = "Remove the key from the artifact; load from backend or Android Keystore; rotate the key.",
            masvs = listOf("MASVS-CRYPTO-1", "MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-STRIPE-SECRET", "Live Stripe secret key (sk_live_/whsec_)", Severity.CRITICAL,
            gates = listOf("sk_live_", "whsec_", "rk_live_"),
            regex = Regex("""\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b|\bwhsec_[0-9a-zA-Z]{16,}\b"""),
            remediation = "Rotate the key immediately in the Stripe dashboard; secret keys must never ship in clients.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-AWS", "AWS access key id embedded", Severity.HIGH,
            gates = listOf("akia", "asia", "abia", "acca", "agpa", "aida", "aroa", "aipa", "anpa", "anva", "asca"),
            regex = Regex("""\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"""),
            remediation = "Delete the key in IAM, rotate, and move any backend calls to your own server.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-AWS-SECRET", "AWS secret access key pattern", Severity.HIGH,
            gates = listOf("aws"),
            regex = Regex("""(?i)aws.{0,25}['"][0-9A-Za-z/+]{40}['"]"""),
            remediation = "Rotate the AWS secret; it must never live in a mobile artifact.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-GOOGLE", "Google API key (AIza…) embedded", Severity.HIGH,
            gates = listOf("aiza"), caseSensitiveGates = listOf("AIza"),
            regex = Regex("""\bAIza[0-9A-Za-z\-_]{35}\b"""),
            remediation = "Restrict the key (package + SHA-1 + API) in Google Cloud console; consider proxying via backend.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-GITHUB", "GitHub token embedded", Severity.CRITICAL,
            gates = listOf("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
            regex = Regex("""\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"""),
            remediation = "Revoke the token in GitHub settings; never ship repo tokens in a client.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-SLACK", "Slack token / webhook embedded", Severity.HIGH,
            gates = listOf("xox", "hooks.slack.com"),
            regex = Regex("""\bxox[abposr]-[A-Za-z0-9-]{10,}\b|https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"""),
            remediation = "Revoke the Slack app token; webhooks are unauthenticated write access to a channel.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-OPENAI", "OpenAI/Anthropic API key embedded", Severity.CRITICAL,
            gates = listOf("sk-proj-", "sk-ant-", "sk-or-v1", "api.openai.com", "api.anthropic.com"),
            regex = Regex("""\b(?:sk-proj-[A-Za-z0-9_\-]{30,}|sk-ant-[A-Za-z0-9_\-]{30,}|sk-or-v1-[a-f0-9]{40,})\b"""),
            remediation = "Keys are billable and allow full account use; rotate now and proxy LLM calls through your backend.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-SENDGRID", "SendGrid/Twilio/Mailgun credential", Severity.HIGH,
            gates = listOf("sg.", "sendgrid", "twilio", "mailgun", "key-"),
            regex = Regex("""\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b|\bAC[0-9a-f]{32}\b|\bkey-[0-9a-f]{32}\b"""),
            remediation = "Rotate the mail credential; sending from a client enables spoofed/phishing mail.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-TELEGRAM", "Telegram bot token embedded", Severity.HIGH,
            gates = listOf("bot", "telegram"),
            regex = Regex("""\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"""),
            remediation = "Revoke the bot token with @BotFather; a leaked token gives full bot control.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-GENERIC", "Hardcoded secret/credential assignment", Severity.MEDIUM,
            gates = listOf("api_key", "apikey", "api-key", "secret", "password", "passwd", "token", "access_key", "client_secret"),
            regex = Regex("""(?i)\b(api[_-]?key|apikey|client[_-]?secret|secret|passwd|password|access[_-]?key|auth[_-]?token)\b["']?\s*[:=]\s*["']?([A-Za-z0-9_\-+=]{16,})["']?"""),
            group = 2,
            // Identifier chains ("request.password") and asset names are not
            // secrets: require a digit and never a Google-key (own rule).
            accept = { _, v -> v.any { it.isDigit() } && !v.startsWith("AIza") && !v.startsWith("SG.") },
            remediation = "Move the value to a backend or use per-user credentials; treat it as leaked if the app shipped.",
            masvs = listOf("MASVS-CRYPTO-1", "MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-ENV-KEY", "Compiled-in environment variable (--dart-define)", Severity.LOW,
            gates = listOf("base_url", "api_url", "endpoint", "client_id", "app_store_id", "delete_password", "sentry_dsn", "supabase_url"),
            regex = Regex("""\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*(?:_URL|_URI|_KEY|_SECRET|_PASSWORD|_TOKEN|_DSN|_ENDPOINT|_ID))\b"""),
            // Only dart-define/envied definitions matter; the same SHOUTY_NAME
            // shape is all over SDK enum constants (RPC_S_*, CLIENT_ID structs).
            accept = { raw, _ ->
                raw.contains("Envied") || raw.contains("varName") ||
                    raw.contains("fromEnvironment") || raw.contains("getEnvironment")
            },
            secret = false,
            note = "The variable name (not its value) is matched: public by design, hypothesis only.",
            remediation = "dart-define values are plaintext in the Dart snapshot; treat them as public. Secrets belong on the server.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-JWT", "Embedded JWT (may be a Supabase/anon or session token)", Severity.MEDIUM,
            gates = listOf("eyj"), caseSensitiveGates = listOf("eyJ", "eyI", "eyP"),
            regex = Regex("""\bey[Ipv][A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"""),
            remediation = "Verify this is a public anon key, not a service-role/session token; restrict row-level security.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-KEY-SUPABASE-SECRET", "Supabase secret (service_role) key embedded", Severity.CRITICAL,
            gates = listOf("sb_secret_"), caseSensitiveGates = listOf("sb_secret_"),
            regex = Regex("""\bsb_secret_[A-Za-z0-9_-]{16,}\b"""),
            remediation = "Rotate the key in the Supabase dashboard; service_role keys bypass RLS and must never ship in a client.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-SUPABASE-PUBLISHABLE", "Supabase publishable (anon) key embedded", Severity.INFO,
            gates = listOf("sb_publishable_"), caseSensitiveGates = listOf("sb_publishable_"),
            regex = Regex("""\bsb_publishable_[A-Za-z0-9_-]{16,}\b"""),
            secret = false,
            note = "Public identifier by design: hypothesis only, not confirmed exploitation.",
            remediation = "Publishable keys are safe to embed; verify RLS is enabled on every exposed table.",
            masvs = listOf("MASVS-CONFIG"),
        ),
        SecretRule(
            "SEC-KEY-OAUTH-CLIENT", "Google OAuth client id exposed", Severity.LOW,
            gates = listOf(".apps.googleusercontent.com"),
            regex = Regex("""\b\d{8,}-[0-9a-z]+\.apps\.googleusercontent\.com\b"""),
            secret = false,
            note = "Public identifier by design: hypothesis only, not confirmed exploitation.",
            remediation = "Client IDs are public by design; verify redirect URIs are locked down.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-FIREBASE", "Firebase project identifiers embedded", Severity.INFO,
            gates = listOf("firebasestorage.app", "firebaseio.com", ":android:", "gcm_defaultsenderid"),
            regex = Regex("""([a-z0-9\-]{3,}\.firebasestorage\.app|[a-z0-9\-]{3,}\.firebaseio\.com|1:\d{6,}:(?:android|web):[0-9a-f]{8,})"""),
            accept = { _, v -> !v.contains("my-awesome-app") && !v.contains("your-") },
            secret = false,
            note = "Public identifier by design: hypothesis only, not confirmed exploitation.",
            remediation = "Firebase IDs/keys are public by design; enforce Security Rules, App Check and API-key restrictions.",
            masvs = listOf("MASVS-CONFIG"),
        ),
        SecretRule(
            "SEC-DB-URI", "Database/broker URI with inline credentials", Severity.CRITICAL,
            gates = listOf("://", "@"),
            regex = Regex("""\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|smtp)://[^:\s/]+:[^@\s/]+@[A-Za-z0-9.\-]+"""),
            group = 0,
            remediation = "Never ship direct database/broker credentials; proxy through an authenticated API and rotate.",
            masvs = listOf("MASVS-CODE-1", "MASVS-NETWORK-1"),
            accept = { _, value ->
                // SDK doc placeholders: mysql://user:password@host:3306/dbname
                val user = value.substringAfter("://").substringBefore(':').lowercase()
                val pass = value.substringAfter("://").substringAfter(':').substringBefore('@').lowercase()
                user !in setOf("user", "username", "dbname", "db", "admin", "root", "test") &&
                    pass !in setOf("password", "pass", "passwd", "secret", "test", "admin", "changeme", "dbname", "host")
            },
        ),
        SecretRule(
            "SEC-BASIC-AUTH-URL", "URL with userinfo (basic-auth credential in URL)", Severity.HIGH,
            gates = listOf("://", "@"),
            regex = Regex("""https?://[^:/\s@]+:[^@/\s]+@[A-Za-z0-9.\-]+"""),
            group = 0,
            // Dart SDK doc comments show http://user:password@localhost:8080.
            accept = { raw, v ->
                val host = v.substringAfter("://").substringAfter('@').lowercase()
                !host.startsWith("localhost") && !host.startsWith("127.") &&
                    !host.startsWith("example.") && !raw.contains("print(") &&
                    !raw.startsWith("//") && !raw.contains("///")
            },
            remediation = "Strip embedded credentials from URLs; use per-user tokens.",
            masvs = listOf("MASVS-NETWORK-1"),
        ),
        SecretRule(
            "SEC-SENTRY-DSN", "Sentry DSN found", Severity.LOW,
            gates = listOf("sentry", "ingest."),
            regex = Regex("""https://[0-9a-f]{32}@[a-z0-9.\-]+/\d+"""),
            secret = false,
            note = "Public identifier by design: hypothesis only, not confirmed exploitation.",
            remediation = "DSNs are client-side identifiers; acceptable if event quotas and PII scrubbing are configured.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-MAPBOX", "Mapbox access token", Severity.LOW,
            gates = listOf("pk.ey"), caseSensitiveGates = listOf("pk.ey"),
            regex = Regex("""\bpk\.ey[A-Za-z0-9_\-=.]{20,}\b"""),
            secret = false,
            note = "Public identifier by design: hypothesis only, not confirmed exploitation.",
            remediation = "Public tokens should be URL-restricted in the Mapbox dashboard.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-REVENUECAT", "RevenueCat SDK key", Severity.LOW,
            gates = listOf("appl_", "goog_", "rc_"),
            regex = Regex("""\b(?:appl|goog|rc)_[A-Za-z0-9]{16,}\b"""),
            secret = false,
            note = "Public identifier by design: hypothesis only, not confirmed exploitation.",
            remediation = "RevenueCat public SDK keys are designed to be embedded; no action unless it is a secret API key.",
            masvs = listOf("MASVS-CODE-1"),
        ),
        SecretRule(
            "SEC-SUPABASE", "Supabase project URL", Severity.INFO,
            gates = listOf(".supabase.co"),
            regex = Regex("""https://[a-z0-9\-]{3,}\.supabase\.co\b"""),
            secret = false,
            note = "Public identifier by design: hypothesis only, not confirmed exploitation.",
            remediation = "Supabase URLs are public; check that RLS policies are enabled on all tables.",
            masvs = listOf("MASVS-CODE-1"),
        ),
    )

    fun toFindingList(): List<Finding> = findings.toList()
}
