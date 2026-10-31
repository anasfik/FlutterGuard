package com.flutterguard.app.scan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.flutterguard.app.scan.parsers.AxmlDecoder
import com.flutterguard.app.scan.parsers.AxmlNode
import com.flutterguard.app.scan.parsers.ArscReader
import com.flutterguard.app.scan.parsers.DexStrings
import com.flutterguard.app.scan.parsers.DotEnv
import com.flutterguard.app.scan.parsers.Notices
import com.flutterguard.app.scan.parsers.Pubspec
import com.flutterguard.app.scan.parsers.SoStrings
import com.flutterguard.app.scan.rules.AssetInventory
import com.flutterguard.app.scan.rules.FlutterRules
import com.flutterguard.app.scan.rules.Layer
import com.flutterguard.app.scan.rules.ManifestRules
import com.flutterguard.app.scan.rules.NetworkRules
import com.flutterguard.app.scan.rules.SecretScanner
import com.flutterguard.app.scan.rules.SigningRules
import com.flutterguard.app.scan.rules.ThirdPartyRules
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.DigestInputStream
import java.security.MessageDigest

/** Thrown by [Scanner.scan] at a cancellation checkpoint after a cancel request. */
class ScanCancelledException : Exception("Scan cancelled")

/** End-to-end static audit of one installed application. */
object Scanner {

    private val skipContentExt = setOf("png", "jpg", "jpeg", "gif", "webp", "ttf", "otf", "zip", "gz", "zst", "mp3", "mp4", "so", "dex", "arsc", "bin", "webm", "woff", "woff2")

    private val keyMaterialExt = setOf("jks", "keystore", "p12", "pfx", "bks", "pem", "key", "pkcs12")

    /** Asset types that commonly carry a baked-in server/node inventory. */
    private val endpointListExt = setOf("yml", "yaml", "toml", "conf", "txt", "csv", "list")

    /** `uri: host:port`, `server = x`, `- host: 1.2.3.4` — no scheme, so urlRegex misses it. */
    private val endpointLine = Regex(
        """^\s*[-]?\s*(?:uri|url|endpoint|host|hosts|server|servers|address|addr|rpc|node|nodes|relay|api)["']?\s*[:=]\s*["']?([a-z0-9](?:[a-z0-9.\-]{2,})\.[a-z]{2,}(?::\d{1,5})?)""",
        RegexOption.IGNORE_CASE,
    )
    /** Marker must be followed closely by a version digit, so doc prose never matches. */
    private val nativeVersionMarkers = Regex(
        """(OpenSSL|SQLite|BoringSSL|libc\+\+|sqlcipher|curl|grpc|libuv|nghttp2)[\s:/,_-]{0,3}v?\d+\.\d+"""
    )

    /**
     * The Dart SDK stamps its own build date into libflutter.so as
     * `3.12.2 (stable) (Tue Jun 9 01:11:39 2026 -0700) on "android_arm64"`.
     * That single line identifies the engine build, which is what a desktop
     * follow-up (Blutter/reFlutter) needs to match.
     */
    private val dartVersionLine = Regex("""\d+\.\d+\.\d+ \((?:stable|beta|dev)\) \(.*\) on "[a-z0-9_]+""")

    /**
     * [isCancelled] is polled at every named stage and inside the long
     * synchronous string loops, so cancellation does not wait for the scan to
     * finish. It throws [ScanCancelledException]; no partial report is produced.
     */
    suspend fun scan(
        context: Context,
        app: InstalledApp,
        onProgress: (step: String, pct: Int) -> Unit,
        isCancelled: () -> Boolean = { false },
    ): Report = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        var flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or PackageManager.GET_PERMISSIONS
        if (Build.VERSION.SDK_INT >= 28) flags = flags or PackageManager.GET_SIGNING_CERTIFICATES
        // Resolved at scan time: the cached InstalledApp carries no platform object,
        // and a package removed since discovery fails here visibly.
        val pi = pm.getPackageInfo(app.packageName, flags)
        val ai = pm.getApplicationInfo(app.packageName, 0)
        ApkSource.forApplication(ai).use { src ->
            scanWith(context, app, src, pi, ai, null, onProgress, isCancelled)
        }
    }

    /**
     * Audits one APK the user picked or shared. There is no PackageManager entry,
     * so identity comes from the decoded manifest and signing is read from the
     * archive (schemes only — no platform certificate chain). Everything after
     * that is the installed-app scan path, unchanged.
     */
    suspend fun scanFile(
        context: Context,
        file: java.io.File,
        onProgress: (step: String, pct: Int) -> Unit,
        isCancelled: () -> Boolean = { false },
    ): Report = withContext(Dispatchers.IO) {
        ApkSource.forFile(file).use { src ->
            val root = src.bytes("AndroidManifest.xml", maxBytes = 8 * 1024 * 1024)
                ?.let { AxmlDecoder.decode(it) }
                ?: throw IllegalArgumentException("No readable AndroidManifest.xml in this file; is it an APK?")
            val meta = fileMeta(root, file.name)
                ?: throw IllegalArgumentException("The manifest declares no package name.")
            val app = InstalledApp(
                packageName = meta.packageName,
                label = meta.label,
                versionName = meta.versionName,
                versionCode = meta.versionCode,
                minSdk = meta.minSdk,
                targetSdk = meta.targetSdk,
                isFlutter = false,
                isSystem = false,
                sizeBytes = file.length(),
                splitCount = 0,
                icon = null,
            )
            scanWith(context, app, src, pi = null, ai = null, manifestHint = root, onProgress, isCancelled)
        }
    }

    /** Package facts a file scan can recover from the manifest alone. */
    data class FileMeta(
        val packageName: String,
        val label: String,
        val versionName: String?,
        val versionCode: Long,
        val minSdk: Int?,
        val targetSdk: Int?,
    )

    /**
     * A name Android would actually install. Enforced because a picked APK is
     * untrusted input and its package name reaches a file name and a navigation
     * route: a crafted value containing the route separator (U+001F) would
     * otherwise decode into a different screen after a restart.
     */
    private val PACKAGE_NAME = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

    fun isInstalledPackageName(name: String): Boolean = PACKAGE_NAME.matches(name)

    /**
     * Manifest identity for a file scan. Resource references (`@ref/0x…`, `@string/…`)
     * are not resolved here, so they fall back to null/placeholder rather than a
     * made-up value. Null when the manifest has no usable package name — absent,
     * a resource reference, or not a name Android would accept.
     */
    fun fileMeta(manifest: AxmlNode, fallbackLabel: String): FileMeta? {
        val pkg = manifest.attr("package")
            ?.takeIf { it.isNotBlank() && !it.startsWith("@") && isInstalledPackageName(it) }
            ?: return null
        val usesSdk = manifest.child("uses-sdk")
        fun attrInt(name: String): Int? =
            manifest.attr(name)?.takeIf { !it.startsWith("@") }?.toIntOrNull()
                ?: usesSdk?.attr(name)?.takeIf { !it.startsWith("@") }?.toIntOrNull()
        val label = manifest.child("application")?.attr("label")
            ?.takeIf { it.isNotBlank() && !it.startsWith("@") }
            ?: fallbackLabel
        return FileMeta(
            packageName = pkg,
            label = label,
            versionName = manifest.attr("versionName")?.takeIf { it.isNotBlank() && !it.startsWith("@") },
            versionCode = attrInt("versionCode")?.toLong() ?: -1L,
            minSdk = attrInt("minSdkVersion"),
            targetSdk = attrInt("targetSdkVersion"),
        )
    }

    private suspend fun scanWith(
        context: Context,
        app: InstalledApp,
        src: ApkSource,
        pi: PackageInfo?,
        ai: ApplicationInfo?,
        manifestHint: AxmlNode?,
        onProgress: (step: String, pct: Int) -> Unit,
        isCancelled: () -> Boolean,
    ): Report {
        val started = System.currentTimeMillis()
        val pm = context.packageManager

        fun check() {
            if (isCancelled()) throw ScanCancelledException()
        }
        fun stage(step: String, pct: Int) {
            check()
            onProgress(step, pct)
        }

        stage("Reading package info", 2)
        stage("Opening APK artifacts", 6)
        return run {
            val zipNames = src.names()
            val findings = ArrayList<Finding>()

            // ---------- manifest ----------
            stage("Decoding AndroidManifest", 10)
            val manifest = manifestHint ?: src.bytes("AndroidManifest.xml")?.let { AxmlDecoder.decode(it) }
            val targetSdk = ai?.targetSdkVersion?.takeIf { it > 0 } ?: app.targetSdk
            val (manifestFindings, facts) = if (manifest != null) {
                ManifestRules.evaluate(context, manifest, targetSdk)
            } else emptyList<Finding>() to ManifestRules.ManifestFacts()
            findings += manifestFindings

            // ---------- metadata ----------
            // Same bytes for an installed app (base + splits) and a picked file.
            val sizeBytes = src.totalBytes()
            val abis = zipNames.asSequence()
                .filter { it.startsWith("lib/") }
                .mapNotNull { it.split("/").getOrNull(1) }
                .toSortedSet()
                .toList()
            val installer = pi?.let {
                runCatching {
                    if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(app.packageName).installingPackageName
                    else @Suppress("DEPRECATION") pm.getInstallerPackageName(app.packageName)
                }.getOrNull()
            }

            // ---------- resources ----------
            stage("Scanning resource strings", 20)
            val scanner = SecretScanner(appTokens(app.packageName, app.label))
            val dexPrefixHits = LinkedHashMap<String, MutableSet<String>>()
            src.bytes("resources.arsc")?.let { arsc ->
                for (s in ArscReader.globalStrings(arsc)) scanner.feed(s, Provenance("resources.arsc"), Layer.ARSC)
            }

            // ---------- res/xml (network security config etc.) ----------
            stage("Decoding res/xml", 26)
            // Resource names are often flattened to res/xx.xml by R8, so match any res/*.xml
            // and identify the config by its root element rather than by filename.
            val resXml = ArrayList<Pair<String, AxmlNode>>()
            for (name in zipNames.filter { it.startsWith("res/") && it.endsWith(".xml") }) {
                src.bytes(name, maxBytes = 4 * 1024 * 1024)?.let { bytes ->
                    AxmlDecoder.decode(bytes)?.let { node -> resXml.add(name to node) }
                }
            }
            val nscCandidates = resXml.filter { it.second.name == "network-security-config" }
            // A stub config with no children carries no policy; prefer a populated one.
            val nsc = (nscCandidates.firstOrNull { it.second.children.isNotEmpty() } ?: nscCandidates.firstOrNull())?.second

            // ---------- DEX ----------
            stage("Extracting DEX strings", 34)
            val dexNames = zipNames.filter { Regex("""^classes\d*\.dex$""").matches(it) }.sorted()
            for (name in dexNames) {
                check()
                val bytes = src.bytes(name, maxBytes = 96 * 1024 * 1024) ?: continue
                var dexStrings = 0
                DexStrings.forEach(bytes, name) { s, srcName, off ->
                    // Bounded checkpoint inside the synchronous string loop.
                    if ((++dexStrings and 0x3FFF) == 0) check()
                    scanner.feed(s, Provenance(srcName, off), Layer.DEX)
                    ThirdPartyRules.checkDexString(s, dexPrefixHits)
                }
            }

            // ---------- native libs ----------
            stage("Analyzing native libraries", 55)
            val primaryAbi = abis.firstOrNull { it == "arm64-v8a" } ?: abis.firstOrNull()
            val nativeLibs = ArrayList<NativeLib>()
            var engineVersionString: String? = null
            var packageUriCount = 0
            var camelCount = 0L
            var libappSha256: String? = null
            var libappAnalyzed = false
            val nativeBridges = LinkedHashSet<String>()
            var jniSymbols = 0

            if (primaryAbi != null) {
                val libEntries = zipNames.filter { it.startsWith("lib/$primaryAbi/") && it.endsWith(".so") }.sorted()
                for (libPath in libEntries) {
                    check()
                    val base = libPath.substringAfterLast('/')
                    val entry = src.entry(libPath) ?: continue
                    val markers = ArrayList<String>()
                    val analyze = base == "libapp.so" || base == "libflutter.so"
                    // Native side libs (Rust/C++ bridges, ffmpeg, crypto engines)
                    // carry their own hosts and keys; 1 MB only covered prefixes.
                    val capBytes = if (analyze) Long.MAX_VALUE else 16L shl 20
                    val stream = src.stream(libPath) ?: continue
                    DigestInputStream(stream, MessageDigest.getInstance("SHA-256")).use { dis ->
                        var soStringsCount = 0
                        SoStrings.forEach(dis, capBytes) { s, off ->
                            if ((soStringsCount and 0xFFFF) == 0) check()
                            if (base == "libapp.so") {
                                if (s.startsWith("package:")) packageUriCount++
                                if (s.length in 8..60 && s.contains(Regex("""^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+$"""))) camelCount++
                                scanner.feed(s, Provenance(libPath, off), Layer.SO)
                            } else {
                                if (base == "libflutter.so" && engineVersionString == null &&
                                    (s.contains("Dart VM version:") || dartVersionLine.containsMatchIn(s))
                                ) {
                                    engineVersionString = s
                                }
                                if (base == "libflutter.so" && soStringsCount < 20000) {
                                    scanner.feed(s, Provenance(libPath, off), Layer.SO)
                                }
                                if (base != "libflutter.so" && soStringsCount < 400000) {
                                    scanner.feed(s, Provenance(libPath, off), Layer.SO)
                                }
                                if (s.length < 80) {
                                    val vm = nativeVersionMarkers.find(s)
                                    if (markers.size < 3 && vm != null) markers.add(s.substring(vm.range.first).take(40))
                                }
                                if (s.startsWith("frb_") || s.contains("flutter_rust_bridge")) {
                                    if (nativeBridges.size < 4) nativeBridges.add("flutter_rust_bridge in $base")
                                }
                                if (s.startsWith("Java_") && s.length < 120 && jniSymbols < 5000) jniSymbols++
                            }
                            soStringsCount++
                        }
                        val sha = dis.messageDigest.digest().joinToString("") { "%02x".format(it) }
                        if (base == "libapp.so") {
                            libappSha256 = sha
                            libappAnalyzed = true
                        }
                        nativeLibs.add(NativeLib(base, primaryAbi, entry.second.size, sha.take(16) + "…", markers))
                    }
                }
            }

            // ---------- Flutter kernel / JIT snapshots ----------
            // Debug Flutter builds ship the Dart kernel (near-source) instead of
            // libapp.so. That blob is the richest evidence source on-device, so it
            // gets a full string sweep — this is what makes a debug APK readable.
            stage("Scanning Dart kernel", 60)
            var kernelBlobBytes: Long? = null
            var snapshotBytes: Long? = null
            val kernelFiles = ArrayList<String>()
            val flutterAssetPrefix = "assets/flutter_assets/"
            val kernelEntries = listOf(
                flutterAssetPrefix + "kernel_blob.bin",
                flutterAssetPrefix + "isolate_snapshot_data",
                flutterAssetPrefix + "vm_snapshot_data",
            )
            for (name in kernelEntries) {
                check()
                val e = src.entry(name) ?: continue
                val size = e.second.size
                if (name.endsWith("kernel_blob.bin")) kernelBlobBytes = size
                else snapshotBytes = (snapshotBytes ?: 0L) + size
                val stream = src.stream(name) ?: continue
                stream.use { ins ->
                    var kernelStrings = 0
                    SoStrings.forEach(ins, 256L * 1024 * 1024) { s, off ->
                        if ((++kernelStrings and 0xFFFF) == 0) check()
                        if (s.startsWith("package:") && s.endsWith(".dart") && kernelFiles.size < 14) {
                            kernelFiles.add(s.take(110))
                        }
                        scanner.feed(s, Provenance(name, off), Layer.KERNEL)
                    }
                }
            }

            // ---------- pub dependency inventory from NOTICES.Z ----------
            // Survives --obfuscate, so it is the fallback when libapp.so symbols
            // are stripped to single letters.
            var noticesPkgs = 0
            src.entry(flutterAssetPrefix + "NOTICES.Z")?.let {
                src.stream(flutterAssetPrefix + "NOTICES.Z")?.use { ins ->
                    val pkgs = Notices.packages(ins)
                    noticesPkgs = pkgs.size
                    for (p in pkgs) if (scanner.dartDeps.size < 600) scanner.dartDeps.add(p)
                }
            }
            if (noticesPkgs > 0) findings += Finding(
                id = "FLUT-NOTICES",
                title = "Dependency inventory recoverable from NOTICES.Z ($noticesPkgs packages)",
                severity = Severity.INFO,
                detail = "NOTICES.Z lists every bundled pub package by name with its license. `--obfuscate` does not " +
                    "remove it, so the third-party stack is always identifiable and each entry maps to a known CVE surface.",
                evidence = emptyList(),
                remediation = "Keep dependencies patched; obfuscation is not confidentiality for the dependency list.",
                masvs = listOf("MASVS-RESILIENCE-1"),
            )

            // ---------- exact dependency versions from pubspec.yaml ----------
            // Release APKs ship the project's pubspec verbatim, so the dependency
            // list is not a guess: names *and* constraints. NOTICES.Z cannot do this.
            src.bytes(flutterAssetPrefix + "pubspec.yaml", 2 * 1024 * 1024)?.let { raw ->
                val info = Pubspec.parse(String(raw, Charsets.UTF_8))
                if (!info.isEmpty) {
                    val shown = info.deps.entries.take(40)
                    findings += Finding(
                        id = "FLUT-PUBSPEC",
                        title = "Exact dependency versions recovered from pubspec.yaml (${info.deps.size})",
                        severity = Severity.INFO,
                        detail = buildString {
                            append("The APK still contains the project's pubspec (")
                            append(info.name ?: "unnamed")
                            info.version?.let { append(' ').append(it) }
                            append(") with exact version constraints, so the third-party stack and the ")
                            append("CVEs that apply to it are identifiable without decompiling.\n")
                            append(shown.joinToString("\n") { (k, v) -> "$k: $v" })
                        },
                        evidence = shown.take(8).map { (k, v) ->
                            Evidence(flutterAssetPrefix + "pubspec.yaml", 0, "$k: $v")
                        },
                        remediation = "Pin and patch dependencies; assume the dependency list is public.",
                        masvs = listOf("MASVS-RESILIENCE-1", "MASVS-CODE-3"),
                    )
                }
            }

            // ---------- assets ----------
            stage("Kernel strings scanned (${scanner.kernelStrings})", 66)
            stage("Scanning assets", 72)
            scanAssets(src, zipNames, scanner, findings, ::check)

            // ---------- name-only inventory: web payloads, config files, SDK markers ----------
            // Nothing is read here, so no content can leak; these are structural facts
            // about what the APK ships, which is exactly what a researcher needs first.
            val inventory = AssetInventory.evaluate(zipNames)
            if (inventory.webPayloads.isNotEmpty()) {
                findings += Finding(
                    id = "WEB-PAYLOAD",
                    title = "Bundled web payload (${inventory.webPayloads.size} page(s), ${inventory.scriptCount} script(s))",
                    severity = Severity.INFO,
                    detail = buildString {
                        append("The APK ships its own HTML/JS, so a WebView renders local content ")
                        append("with whatever bridge the app exposes. Review the bridge markers above ")
                        append("together with these pages.\n")
                        append(inventory.webPayloads.take(20).joinToString("\n"))
                        if (inventory.webPayloads.size > 20) append("\n…")
                    },
                    evidence = inventory.webPayloads.take(8).map { Evidence(it, 0, it) },
                    remediation = "Serve remote content over TLS where possible; expose no JS interface to local pages that can be replaced.",
                    masvs = listOf("MASVS-PLATFORM-1"),
                )
            }
            if (inventory.sdkMarkers.isNotEmpty()) {
                findings += Finding(
                    id = "SDK-MARKER",
                    title = "SDK marker files (${inventory.sdkMarkers.size})",
                    severity = Severity.INFO,
                    detail = inventory.sdkMarkers.entries.joinToString("\n") { (sdk, files) ->
                        "$sdk: ${files.joinToString(", ")}"
                    },
                    evidence = inventory.sdkMarkers.entries.flatMap { (sdk, files) ->
                        files.map { Evidence(it, 0, sdk) }
                    }.take(8),
                    remediation = "Confirms the bundled SDK set; keep those SDKs patched.",
                    masvs = listOf("MASVS-RESILIENCE-3"),
                )
            }
            if (inventory.configFiles.isNotEmpty()) {
                findings += Finding(
                    id = "AST-CONFIG",
                    title = "Bundled config/secret-bearing files (${inventory.configFiles.size})",
                    severity = Severity.INFO,
                    detail = "Files that commonly carry endpoints, keys or database content:\n" +
                        inventory.configFiles.take(25).joinToString("\n"),
                    evidence = inventory.configFiles.take(8).map { Evidence(it, 0, it) },
                    remediation = "Ship no development config; keep credentials out of anything under assets/.",
                    masvs = listOf("MASVS-STORAGE-1"),
                )
            }

            // ---------- rule sets that consume aggregates ----------
            stage("Evaluating network security", 80)
            val nscDeclared = manifest?.children("application")?.firstOrNull()?.attr("networkSecurityConfig") != null
            findings += NetworkRules.evaluate(nsc, facts.usesCleartextTraffic, targetSdk ?: facts.targetSdkAttr, scanner.httpHosts, nscDeclared)

            stage("Verifying signing", 85)
            val (signing, sigFindings) = if (pi != null && ai?.publicSourceDir != null) {
                SigningRules.evaluate(pi, ai.publicSourceDir ?: "", zipNames)
            } else {
                SigningRules.forFile(src.primaryFile, zipNames)
            }
            findings += sigFindings

            val (fwInfo, flutterFindings) = FlutterRules.evaluate(
                zipNames, engineVersionString, libappAnalyzed, packageUriCount, camelCount, libappSha256,
                kernelBlobBytes, snapshotBytes, kernelFiles,
            )
            findings += flutterFindings
            val framework = fwInfo.copy(dartDeps = scanner.dartDeps.toList())

            // ---------- WebView / bridge findings ----------
            for ((marker, desc) in scanner.dexMarkers) {
                val sev = when {
                    marker == "setAllowFileAccessFromFileURLs" || marker == "setAllowUniversalAccessFromFileURLs" -> Severity.HIGH
                    marker == "addJavascriptInterface" || marker == "JavascriptInterface" -> Severity.MEDIUM
                    marker == "setWebContentsDebuggingEnabled" || marker == "onReceivedSslError" -> Severity.MEDIUM
                    else -> Severity.INFO
                }
                findings += Finding(
                    id = "WEB-$marker",
                    title = "WebView surface: $marker",
                    severity = sev,
                    detail = desc,
                    evidence = emptyList(),
                    remediation = "Restrict bridge exposure; never enable file/universal access; debug flags off in release.",
                    masvs = listOf("MASVS-PLATFORM-2"),
                )
            }
            val customChannels = scanner.channels.filter { it.value.second == "app" || it.value.second == "custom" }
            if (customChannels.isNotEmpty()) findings += Finding(
                id = "FLUT-CHANNELS",
                title = "Custom platform channels (${customChannels.size})",
                severity = Severity.LOW,
                detail = "Non-standard MethodChannel/EventChannel names reachable from the Dart side: " +
                    customChannels.keys.take(10).joinToString() + (if (customChannels.size > 10) " …" else "") +
                    ". Each is bridge attack surface if arguments are not validated.",
                evidence = emptyList(),
                remediation = "Validate channel arguments; do not expose sensitive primitives over custom channels.",
                masvs = listOf("MASVS-PLATFORM-2"),
            )

            // ---------- Dart-layer TLS / proxy findings ----------
            for ((marker, desc) in scanner.dartMarkers) {
                val tlsBypass = marker == "badCertificateCallback"
                findings += Finding(
                    id = "FLUT-TLS-$marker",
                    title = "Dart TLS surface: $marker",
                    severity = if (tlsBypass) Severity.MEDIUM else Severity.INFO,
                    detail = "$desc. Reachable from Dart code compiled into the app" +
                        if (tlsBypass) ", so an on-path attacker can be accepted as trusted when the callback returns true." else ".",
                    evidence = emptyList(),
                    remediation = "Do not relax certificate validation in production; pin the expected server certificates instead.",
                    masvs = listOf("MASVS-NETWORK-2"),
                )
            }
            if (scanner.proxySchemes.isNotEmpty()) findings += Finding(
                id = "FLUT-PROXY-APP",
                title = "Proxy/VPN client surface (${scanner.proxySchemes.joinToString()})",
                severity = Severity.INFO,
                detail = "The Dart layer implements or imports proxy URI handlers: " +
                    scanner.proxySchemes.joinToString() + "://. Expect runtime-supplied server configs, " +
                    "user-pasted subscription URLs and embedded tunnelling stacks — the endpoint inventory " +
                    "of such an app is mostly dynamic.",
                evidence = emptyList(),
                remediation = "Treat pasted configs as untrusted input; never log subscription URLs or keys.",
                masvs = listOf("MASVS-NETWORK-1"),
            )

            if (scanner.privateKeyFound) findings += Finding(
                id = "SEC-PRIVATE-KEY",
                title = "Private key material inside the artifact",
                severity = Severity.CRITICAL,
                detail = "A PEM private-key header is embedded in the APK. The key is public with the artifact: " +
                    "it can decrypt bundled data, sign as the app, or authenticate to whatever trusts it.",
                evidence = emptyList(),
                remediation = "Revoke and rotate the key, remove it from the build, and keep signing on the build server.",
                masvs = listOf("MASVS-CRYPTO-1", "MASVS-CODE-4"),
            )
            if (scanner.x509Certs.isNotEmpty()) findings += Finding(
                id = "CRYPTO-X509",
                title = "Certificate embedded in the app (${scanner.x509Certs.size})",
                severity = Severity.INFO,
                detail = "An X.509 certificate travels with the APK: " + scanner.x509Certs.joinToString("; ") +
                    ". That is the identity the client trusts or pins — it names the backend and the key owner " +
                    "even when no hostname is hardcoded.",
                evidence = scanner.x509Certs.map { Evidence("x509", 0, it) },
                remediation = "Expected for pinned backends; make sure the matching private key is server-side only.",
                masvs = listOf("MASVS-NETWORK-2"),
            )
            if (scanner.pinMaterial.isNotEmpty()) findings += Finding(
                id = "NET-PIN-MATERIAL",
                title = "Certificate pin material in the artifact (${scanner.pinMaterial.size})",
                severity = Severity.INFO,
                detail = "TLS pinning hashes are compiled into the app: " + scanner.pinMaterial.joinToString() +
                    ". Pinning raises the bar for on-path interception, but the pin set rotates from the artifact, " +
                    "so an expired pin bricks the app and the hashes themselves are public.",
                evidence = scanner.pinMaterial.map { Evidence("pins", 0, it) },
                remediation = "Ship pins with a backup pin and a rotation plan; never rely on pinning for secrets.",
                masvs = listOf("MASVS-NETWORK-2"),
            )

            // ---------- native bridge surface ----------
            if (nativeBridges.isNotEmpty()) findings += Finding(
                id = "FLUT-NATIVE-BRIDGE",
                title = "Native bridge in the process (${nativeBridges.size})",
                severity = Severity.INFO,
                detail = "Foreign-function bridge detected: " + nativeBridges.joinToString() +
                    ". Bridge libraries ship business logic and string data outside libapp.so, so AOT " +
                    "obfuscation does not cover them and their strings are readable with a plain dump.",
                evidence = nativeBridges.map { Evidence("native", 0, it) },
                remediation = "Keep secrets server-side; treat the bridge layer as inspectable.",
                masvs = listOf("MASVS-RESILIENCE-1"),
            )
            if (jniSymbols > 50) findings += Finding(
                id = "FLUT-JNI-SURFACE",
                title = "JNI entry points exposed ($jniSymbols Java_* symbols)",
                severity = Severity.INFO,
                detail = "$jniSymbols Java_* native entry points are exported by the packaged libraries. Each is a " +
                    "callable boundary from managed code into native code; combined with a debuggable build they " +
                    "are the usual hooks for runtime instrumentation.",
                evidence = emptyList(),
                remediation = "Keep native entry points narrow and validate every argument crossing the boundary.",
                masvs = listOf("MASVS-RESILIENCE-1"),
            )

            // ---------- third party ----------
            val thirdParty = ThirdPartyRules.detect(zipNames, dexPrefixHits, scanner.dartDeps, scanner.hosts)
            findings += scanner.toFindingList()

            // ---------- assemble ----------
            stage("Composing report", 95)
            val all = findings.sortedBy { it.severity }
            val counts = Severity.entries.associateWith { s -> all.count { it.severity == s } }
            val meta = AppMeta(
                packageName = app.packageName,
                label = app.label,
                versionName = pi?.versionName ?: app.versionName,
                versionCode = pi?.let { if (Build.VERSION.SDK_INT >= 28) it.longVersionCode else it.versionCode.toLong() }
                    ?: app.versionCode,
                minSdk = facts.minSdkAttr ?: ai?.minSdkVersion?.takeIf { it > 0 } ?: app.minSdk,
                targetSdk = targetSdk ?: facts.targetSdkAttr,
                installer = installer,
                firstInstallMs = pi?.firstInstallTime ?: 0,
                lastUpdateMs = pi?.lastUpdateTime ?: 0,
                isSystem = app.isSystem,
                sizeBytes = sizeBytes,
                splitCount = (src.partCount - 1).coerceAtLeast(0),
                abis = abis,
                nativeLibs = nativeLibs,
                baseSha256 = src.primaryFile?.let { runCatching { ApkSource.sha256(it) }.getOrNull() } ?: "",
                fileScan = pi == null,
            )
            val stats = ReportStats(
                critical = counts[Severity.CRITICAL] ?: 0,
                high = counts[Severity.HIGH] ?: 0,
                medium = counts[Severity.MEDIUM] ?: 0,
                low = counts[Severity.LOW] ?: 0,
                info = counts[Severity.INFO] ?: 0,
                stringsScanned = scanner.stringsScanned,
                durationMs = System.currentTimeMillis() - started,
            )
            val grade = gradeOf(stats.critical, stats.high, stats.medium, stats.low)
            // Notable artifact rows only: the full inventory is browsable live
            // through ApkSource; the report carries a bounded, deterministic subset.
            val notableCategories = setOf(
                ArtifactCategory.MANIFEST, ArtifactCategory.DEX, ArtifactCategory.NATIVE_LIB,
                ArtifactCategory.KERNEL, ArtifactCategory.CONFIG, ArtifactCategory.KEY_MATERIAL,
                ArtifactCategory.SIGNING,
            )
            val notableArtifacts = runCatching { src.artifactEntries() }.getOrDefault(emptyList())
                .filter { it.category in notableCategories }
                .sortedWith(compareBy<ArtifactEntry> { it.category.ordinal }.thenBy { it.name })
                .take(256)
            val report = Report(
                meta, framework, signing, all,
                scanner.hostInfos(),
                scanner.channels.map { (n, v) -> ChannelInfo(n, v.first, v.second) }.sortedBy { it.kind },
                thirdParty, facts.permissionHits, facts.deepLinks, stats, grade,
                routes = scanner.routes.toList(),
                dartSources = scanner.dartSources.toList(),
                artifacts = notableArtifacts,
            ).let { r -> r.scrubSecrets(r.secretValues()) }
            stage("Done", 100)
            report
        }
    }

    private val tokenStopWords = setOf(
        "com", "org", "net", "io", "app", "apps", "dev", "prod", "android", "flutter",
        "main", "the", "mobile", "client", "release", "debug", "example", "test",
    )

    /** Package/label tokens used to tell the app's own hosts from SDK/docs noise. */
    private fun appTokens(pkg: String, label: String): Set<String> =
        (pkg.lowercase().split('.', '_', '-') + label.lowercase().split(' ', '_', '-'))
            .filter { it.length >= 4 && it !in tokenStopWords }
            .toSet()

    private fun scanAssets(
        src: ApkSource,
        zipNames: Set<String>,
        scanner: SecretScanner,
        findings: MutableList<Finding>,
        check: () -> Unit,
    ) {
        val interesting = listOf(
            ".env" to Severity.HIGH, "google-services.json" to Severity.MEDIUM,
            "secrets" to Severity.MEDIUM, "credentials" to Severity.MEDIUM,
        )
        var endpointHits = 0
        for (name in zipNames) {
            check()
            // Root-level config files (firebase-*.properties, *.json, *.cfg) are
            // just as readable as assets/ and routinely carry project ids and keys.
            val rootConfig = !name.contains('/') &&
                (name.endsWith(".properties") || name.endsWith(".json") || name.endsWith(".cfg") || name.endsWith(".ini"))
            if (!name.startsWith("assets/") && !name.startsWith("res/raw/") && !rootConfig) continue
            val ext = name.substringAfterLast('.', "").lowercase()
            if (ext in skipContentExt) continue
            val lower = name.lowercase()

            // Key material inside the artifact is directly exploitable, unlike a
            // public API key: a bundled keystore or PEM can sign or decrypt.
            if (ext in keyMaterialExt) findings += Finding(
                id = "AST-KEYMATERIAL",
                title = "Signing/private key material bundled",
                severity = Severity.HIGH,
                detail = "$name ships inside the APK. Anyone with the artifact can extract it and reuse the key " +
                    "to sign updates, decrypt bundled data or impersonate the client.",
                evidence = emptyList(),
                remediation = "Remove key material from the app; keep keystores and PEMs on the build server only.",
                masvs = listOf("MASVS-CODE-4", "MASVS-CRYPTO-1"),
            )

            // Server/node inventories ship as plain YAML/JSON/config with bare
            // `host:port` values, which the URL harvester cannot see.
            if (ext in endpointListExt && endpointHits < 200) {
                val bytes = src.bytes(name, maxBytes = 256 shl 10)
                if (bytes != null) {
                    var applied = 0
                    for (line in String(bytes, Charsets.UTF_8).lineSequence()) {
                        if (line.length > 200) continue
                        val host = endpointLine.find(line)?.groupValues?.get(1) ?: continue
                        scanner.feed("https://$host", Provenance(name, 0), Layer.ASSET)
                        endpointHits++
                        applied++
                        if (applied >= 40 || endpointHits >= 200) break
                    }
                }
            }

            // filename-based signals
            if (lower == "assets/google-services.json" || lower.endsWith("/google-services.json")) {
                val bytes = src.bytes(name, maxBytes = 1 shl 20)
                var detail = "Firebase configuration file bundled in assets."
                val fields = ArrayList<String>()
                if (bytes != null) {
                    runCatching {
                        val json = org.json.JSONObject(String(bytes, Charsets.UTF_8))
                        json.optJSONObject("project_info")?.let { p ->
                            p.optString("project_id", "").takeIf { it.isNotEmpty() }?.let { fields.add("project_id=$it") }
                            p.optString("storage_bucket", "").takeIf { it.isNotEmpty() }?.let { fields.add("bucket=$it") }
                        }
                        json.optJSONArray("client")?.optJSONObject(0)?.optJSONObject("api_key")?.optJSONArray("current_key")?.optString(0)?.takeIf { it.isNotEmpty() }?.let { fields.add("api_key=${Evidence.mask(it)}") }
                    }
                }
                if (fields.isNotEmpty()) detail += " (${fields.joinToString()})"
                findings += Finding(
                    id = "AST-FIREBASE-JSON",
                    title = "google-services.json bundled",
                    severity = Severity.MEDIUM,
                    detail = detail,
                    evidence = emptyList(),
                    remediation = "Firebase config is public by design; verify API key restrictions.",
                    masvs = listOf("MASVS-CONFIG"),
                )
            }
            if (lower.endsWith(".env") || lower.endsWith(".env.json") || lower.contains("/.env")) {
                val dotenv = if (lower.endsWith(".env.json")) emptyList() else {
                    val bytes = src.bytes(name, maxBytes = 256 * 1024)
                    if (bytes == null) emptyList() else DotEnv.parse(String(bytes, Charsets.UTF_8))
                }
                val creds = dotenv.filter {
                    DotEnv.isSecret(it.name) && it.value.length >= 8 &&
                        it.value.lowercase() !in setOf("true", "false", "null", "none")
                }
                if (dotenv.isNotEmpty()) {
                    // Feed every value back through the secret rules: a dotenv file is
                    // the highest-signal text in the whole artifact.
                    for (e in dotenv) scanner.feed("${e.name}=${e.value}", Provenance(name, 0), Layer.ASSET)
                    val live = lower.contains("prod") || lower.contains("live")
                    findings += Finding(
                        id = "AST-DOTENV",
                        title = "Environment file shipped: ${name.substringAfterLast('/')} (${dotenv.size} vars, ${creds.size} credentials)",
                        severity = when {
                            creds.isNotEmpty() && live -> Severity.CRITICAL
                            creds.isNotEmpty() -> Severity.HIGH
                            else -> Severity.MEDIUM
                        },
                        detail = "$name is bundled in plain text and defines ${dotenv.size} variables, " +
                            if (creds.isNotEmpty()) "${creds.size} of which are named like credentials" +
                                (if (live) " in a production/live profile" else "") +
                                ". Extracted: " + creds.map { it.name }.joinToString()
                            else ". No credential-shaped names, but endpoints and flags are public.",
                        evidence = creds.take(12).map {
                            Evidence(name, 0, it.name + "=" + Evidence.mask(it.value), it.value)
                        },
                        remediation = "Ship only public configuration in the app; keep client secrets server-side and inject them at runtime.",
                        masvs = listOf("MASVS-CRYPTO-1", "MASVS-CONFIG"),
                    )
                } else findings += Finding(
                    id = "AST-ENV",
                    title = "dotenv-style file bundled: $name",
                    severity = Severity.HIGH,
                    detail = "Environment files shipped inside the artifact frequently carry API keys and endpoints.",
                    evidence = emptyList(),
                    remediation = "Move secrets to the backend; rebuild without bundling .env files.",
                    masvs = listOf("MASVS-CRYPTO-1"),
                )
            }
            if (ext in setOf("keystore", "jks", "p12", "pem")) {
                findings += Finding(
                    id = "AST-KEYFILE",
                    title = "Key/keystore file bundled: $name",
                    severity = Severity.HIGH,
                    detail = "A keystore/certificate file ships inside the APK assets.",
                    evidence = emptyList(),
                    remediation = "Remove bundled key material; rotate exposed keys.",
                    masvs = listOf("MASVS-CRYPTO-1"),
                )
            }

            // content scan for small text-ish files
            val pair = src.entry(name) ?: continue
            if (pair.second.size <= 0 || pair.second.size > (2L shl 20)) continue
            src.stream(name)?.use { ins ->
                val head = ByteArray(minOf(4096, pair.second.size.toInt()).coerceAtLeast(1))
                var r = 0
                while (r < head.size) { val n = ins.read(head, r, head.size - r); if (n <= 0) break; r += n }
                var printable = 0
                for (b in head) if (b in 0x20..0x7E || b == 0x0A.toByte() || b == 0x09.toByte() || b == 0x0D.toByte()) printable++
                if (r > 0 && printable * 100 / r >= 85) {
                    SoStrings.forEach(java.io.SequenceInputStream(java.io.ByteArrayInputStream(head, 0, r), ins), 2L shl 20) { s, off ->
                        scanner.feed(s, Provenance(name, off), Layer.ASSET)
                    }
                }
            }
        }
    }
}
