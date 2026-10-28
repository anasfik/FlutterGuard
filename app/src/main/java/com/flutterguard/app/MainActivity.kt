package com.flutterguard.app

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.flutterguard.app.scan.Discovery
import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.History
import com.flutterguard.app.scan.InstalledApp
import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.ReportExport
import com.flutterguard.app.scan.Scanner
import com.flutterguard.app.scan.Severity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.DateFormat
import java.util.Date

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Headless mode for scripted audits:
        //   adb shell am start -n com.flutterguard.app/.MainActivity -e scan com.example.app
        // Writes files/reports/<pkg>.json and logs "FG_REPORT <path>".
        val target = intent?.getStringExtra("scan")
        if (!target.isNullOrBlank()) {
            runHeadless(target)
            return
        }
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Color(0xFF64FFDA), surface = Color(0xFF161B22), background = Color(0xFF0E1116))) {
                AppNav()
            }
        }
    }

    private fun runHeadless(pkg: String) {
        // Process-scoped, not lifecycle-scoped: a scan takes ~100s and must keep
        // running when the activity is backgrounded or finished.
        Headless.scope.launch {
            android.util.Log.i("FlutterGuard", "FG_START $pkg")
            val result = runCatching {
                val app = Discovery.loadApps(this@MainActivity).firstOrNull { it.packageName == pkg }
                    ?: error("not installed: $pkg")
                val r = Scanner.scan(this@MainActivity, app) { stage, pct ->
                    android.util.Log.i("FlutterGuard", "FG_PROGRESS $pct% $stage")
                }
                val dir = reportsDir(this@MainActivity)
                val base = pkg.replace('.', '_')
                val f = File(dir, base + ".json")
                f.writeText(ReportExport.toJson(r))
                File(dir, base + ".hist").writeText(History.snapshot(r))
                f.absolutePath
            }
            result.onSuccess { android.util.Log.i("FlutterGuard", "FG_REPORT $it") }
                .onFailure { android.util.Log.e("FlutterGuard", "FG_ERROR ${it.message}") }
            finish()
        }
    }
}

private object Headless {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
}

// ---------------------------------------------------------------- navigation

private sealed interface Screen {
    data object List : Screen
    data class Audit(val app: InstalledApp) : Screen
}

/**
 * Reports live in app-specific external storage so `adb pull` works on the signed
 * release build, where the package is not debuggable and `run-as` is refused.
 */
private fun reportsDir(context: android.content.Context): File =
    File(context.getExternalFilesDir(null) ?: context.filesDir, "reports").apply { mkdirs() }

@Composable
private fun AppNav() {
    var screen by remember { mutableStateOf<Screen>(Screen.List) }
    when (val s = screen) {
        Screen.List -> AppListScreen(onPick = { screen = Screen.Audit(it) })
        is Screen.Audit -> AuditScreen(app = s.app, onBack = { screen = Screen.List })
    }
}

// ---------------------------------------------------------------- list screen

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppListScreen(onPick: (InstalledApp) -> Unit) {
    val context = LocalContext.current
    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var query by remember { mutableStateOf("") }
    var flutterOnly by remember { mutableStateOf(true) }
    var hideSystem by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) { runCatching { Discovery.loadApps(context) }.getOrDefault(emptyList()) }
        loading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("FlutterGuard", fontWeight = FontWeight.Bold) },
                actions = {
                    Text("on-device · no network", fontSize = 11.sp, color = Color(0xFF8B949E), modifier = Modifier.padding(end = 12.dp))
                },
            )
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            OutlinedTextField(
                value = query, onValueChange = { query = it },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                placeholder = { Text("Search installed apps…") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
            )
            Row(Modifier.padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = flutterOnly, onClick = { flutterOnly = !flutterOnly }, label = { Text("Flutter only") })
                FilterChip(selected = hideSystem, onClick = { hideSystem = !hideSystem }, label = { Text("Hide system") })
            }
            if (loading) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(12.dp))
                    Text("Enumerating installed apps…")
                }
            } else {
                val flutterCount = apps.count { it.isFlutter }
                var effectiveFlutterOnly = flutterOnly
                var note: String? = null
                if (flutterOnly && flutterCount == 0) {
                    effectiveFlutterOnly = false
                    note = "No Flutter apps detected — showing all user apps instead."
                }
                val filtered = apps.filter {
                    (query.isBlank() || it.label.contains(query, true) || it.packageName.contains(query, true)) &&
                        (!effectiveFlutterOnly || it.isFlutter) && (!hideSystem || !it.isSystem)
                }
                Text(
                    note ?: "${filtered.size} shown · ${flutterCount} Flutter apps on device",
                    fontSize = 12.sp, color = Color(0xFF8B949E),
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                )
                LazyColumn {
                    items(filtered, key = { it.packageName }) { app ->
                        AppRow(app, onPick)
                    }
                }
            }
        }
    }
}

@Composable
private fun AppRow(app: InstalledApp, onPick: (InstalledApp) -> Unit) {
    Row(
        Modifier.fillMaxWidth()
            .clickable { onPick(app) }
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        app.icon?.let {
            Image(it.asImageBitmap(), contentDescription = null, Modifier.size(40.dp))
        } ?: Box(Modifier.size(40.dp).background(Color(0xFF30363D), CircleShape))
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(app.label, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(app.packageName, fontSize = 12.sp, color = Color(0xFF8B949E), maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        if (app.isFlutter) {
            Surface(color = Color(0xFF1B2A1F), shape = RoundedCornerShape(4.dp)) {
                Text("  FLUTTER  ", fontSize = 10.sp, color = Color(0xFF64FFDA), fontFamily = FontFamily.Monospace)
            }
        }
    }
}

// ---------------------------------------------------------------- audit screen

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AuditScreen(app: InstalledApp, onBack: () -> Unit) {
    val context = LocalContext.current
    var report by remember { mutableStateOf<Report?>(null) }
    var diff by remember { mutableStateOf<List<String>>(emptyList()) }
    var step by remember { mutableStateOf("starting…") }
    var pct by remember { mutableStateOf(0) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(app.packageName) {
        try {
            val dir = reportsDir(context)
            val base = app.packageName.replace('.', '_')
            val histFile = File(dir, "$base.hist")
            val previous = runCatching { histFile.readText() }.getOrNull()
            report = Scanner.scan(context, app) { s, p -> step = s; pct = p }
            val current = report!!
            if (previous != null) diff = History.diff(previous, History.snapshot(current))
            // Keep every UI scan exportable: same file the headless mode writes.
            runCatching {
                val f = File(dir, "$base.json")
                f.writeText(ReportExport.toJson(current))
                histFile.writeText(History.snapshot(current))
                Log.i("FlutterGuard", "FG_REPORT ${f.absolutePath}")
            }
        } catch (t: Throwable) {
            error = t.message ?: t.toString()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Column { Text(app.label, maxLines = 1, overflow = TextOverflow.Ellipsis); Text(app.packageName, fontSize = 11.sp, color = Color(0xFF8B949E)) } },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            when {
                error != null -> ErrorCard(error!!)
                report == null -> ProgressUI(step, pct)
                else -> ReportView(report!!, diff)
            }
        }
    }
}

@Composable
private fun ProgressUI(step: String, pct: Int) {
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center) {
        CircularProgressIndicator()
        Spacer(Modifier.height(20.dp))
        Text("Auditing…", fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        LinearProgressIndicator(progress = { pct / 100f }, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(8.dp))
        Text("$step  ($pct%)", fontSize = 12.sp, color = Color(0xFF8B949E))
    }
}

@Composable
private fun ErrorCard(msg: String) {
    Card(Modifier.fillMaxWidth().padding(16.dp), colors = CardDefaults.cardColors(containerColor = Color(0xFF2D1B1B))) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Warning, tint = Color(0xFFB3261E), contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Could not audit this app", fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(8.dp))
            Text(msg, fontSize = 12.sp)
            Spacer(Modifier.height(8.dp))
            Text(
                "If this is a Permission denied / EACCES on reading base.apk, this ROM (e.g. MIUI/HyperOS) blocks reading other apps' APKs. Stock Android allows it.",
                fontSize = 11.sp, color = Color(0xFF8B949E),
            )
        }
    }
}

// ---------------------------------------------------------------- report view

private val sevColor = mapOf(
    Severity.CRITICAL to Color(0xFFFF5252),
    Severity.HIGH to Color(0xFFFF9800),
    Severity.MEDIUM to Color(0xFFFDD835),
    Severity.LOW to Color(0xFF90A4AE),
    Severity.INFO to Color(0xFF64B5F6),
)

@Composable
private fun ReportView(r: Report, diff: List<String> = emptyList()) {
    val context = LocalContext.current
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {

        // grade header
        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF161B22))) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(r.grade.toString(), fontSize = 56.sp, fontWeight = FontWeight.Black,
                    color = when (r.grade) { 'A' -> Color(0xFF69F0AE); 'B' -> Color(0xFFAEEA00); 'C' -> Color(0xFFFDD835); 'D' -> Color(0xFFFF9800); else -> Color(0xFFFF5252) })
                Spacer(Modifier.width(16.dp))
                Column {
                    SeverityChip("CRITICAL", r.stats.critical, Severity.CRITICAL)
                    SeverityChip("HIGH", r.stats.high, Severity.HIGH)
                    SeverityChip("MEDIUM", r.stats.medium, Severity.MEDIUM)
                    SeverityChip("LOW · INFO", r.stats.low + r.stats.info, Severity.LOW)
                    Text("${r.stats.stringsScanned} strings · ${r.stats.durationMs / 1000}s", fontSize = 11.sp, color = Color(0xFF8B949E))
                }
            }
        }

        if (diff.isNotEmpty()) Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF161B22))) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text("Changes since last scan", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF58A6FF))
                diff.forEach { line ->
                    Text(
                        line,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = when (line.firstOrNull()) {
                            '+' -> Color(0xFFF85149)
                            '-' -> Color(0xFF3FB950)
                            else -> Color(0xFF8B949E)
                        },
                    )
                }
            }
        }

        InfoCard("Artifact") {
            InfoLine("Version", "${r.meta.versionName ?: "?"} (${r.meta.versionCode})")
            InfoLine("SDK", "min ${r.meta.minSdk ?: "?"} → target ${r.meta.targetSdk ?: "?"}")
            InfoLine("Size / splits", "${r.meta.sizeBytes / 1024 / 1024} MB · ${r.meta.splitCount} split(s)")
            InfoLine("ABIs", r.meta.abis.joinToString().ifEmpty { "none" })
            InfoLine("Installer", r.meta.installer ?: "unknown/sideloaded")
            if (r.meta.baseSha256.isNotEmpty()) InfoLine("base.apk SHA-256", r.meta.baseSha256.take(24) + "…")
            r.meta.nativeLibs.take(6).forEach { l ->
                Row(Modifier.padding(vertical = 1.dp)) {
                    Text(
                        l.name,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = Color(0xFF8B949E),
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        "${l.sizeBytes / 1024} KB",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }

        InfoCard("Framework") {
            if (r.framework.isFlutter) {
                InfoLine("Flutter", "yes — ${r.framework.buildMode ?: "?"}")
                InfoLine("Dart", r.framework.dartVersion ?: "unknown")
                InfoLine("Obfuscated", r.framework.obfuscated?.toString() ?: "n/a")
                r.framework.kernelBlobBytes?.let { InfoLine("kernel_blob.bin", "${it / 1024 / 1024} MB — readable Dart") }
                r.framework.snapshotBytes?.let { if (it > 0) InfoLine("JIT snapshots", "${it / 1024 / 1024} MB") }
                if (r.framework.engineDebug) InfoLine("Engine", "debug build")
                if (r.framework.dartDeps.isNotEmpty()) InfoLine("Dart deps", "${r.framework.dartDeps.size}: " + r.framework.dartDeps.take(10).joinToString())
                if (r.framework.engineVersion != null) InfoLine("Engine", r.framework.engineVersion!!.take(80))
            } else {
                InfoLine("Flutter", "no")
                if (r.framework.otherFrameworks.isNotEmpty()) InfoLine("Detected", r.framework.otherFrameworks.joinToString())
            }
        }

        InfoCard("Signing") {
            InfoLine("Schemes", r.signing.schemes.joinToString(" / ").ifEmpty { "none detected" })
            InfoLine("Signer", r.signing.signerSubject ?: "?")
            InfoLine("SHA-256", r.signing.sha256Fingerprint?.let { it.take(24) + "…" } ?: "?")
            if (r.signing.debugCert) InfoLine("DEBUG CERT", "signed with Android Debug certificate")
            InfoLine("Valid until", r.signing.validTo ?: "?")
            r.signing.notes.forEach { Text("· $it", fontSize = 11.sp, color = Color(0xFF8B949E)) }
        }

        // findings
        Text("Findings (${r.findings.size})", fontWeight = FontWeight.Bold, fontSize = 16.sp)
        if (r.findings.isEmpty()) Text("No findings — remarkably clean.", color = Color(0xFF69F0AE))
        Severity.entries.forEach { sev ->
            r.bySeverity[sev]?.forEach { f -> FindingCard(f) }
        }

        val namedHosts = r.hosts.filter { it.classification != "unclassified" }
        CollapsibleCard("Endpoints (${namedHosts.size})") {
            namedHosts.take(40).forEach { h ->
                Row(Modifier.padding(vertical = 1.dp)) {
                    Text(
                        h.host,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        if (h.appOwned) "app" else h.classification,
                        fontSize = 10.sp,
                        color = if (h.appOwned) Color(0xFF3FB950) else Color(0xFF8B949E),
                    )
                }
                h.samples.take(2).forEach { s ->
                    Text("   $s", fontSize = 10.sp, color = Color(0xFF8B949E), fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            val hidden = r.hosts.size - namedHosts.size
            if (hidden > 0) Text("+ $hidden doc/library host(s) in JSON export", fontSize = 10.sp, color = Color(0xFF8B949E))
        }
        if (r.routes.isNotEmpty()) CollapsibleCard("API routes (${r.routes.size})") {
            r.routes.forEach { Text("· $it", fontSize = 11.sp, fontFamily = FontFamily.Monospace) }
        }
        if (r.dartSources.isNotEmpty()) CollapsibleCard("Dart source files (${r.dartSources.size})") {
            r.dartSources.forEach { Text("· $it", fontSize = 11.sp, fontFamily = FontFamily.Monospace) }
        }
        if (r.framework.dartDeps.isNotEmpty()) CollapsibleCard("Dart dependencies (${r.framework.dartDeps.size})") {
            Text(r.framework.dartDeps.joinToString(", "), fontSize = 11.sp, fontFamily = FontFamily.Monospace)
        }
        CollapsibleCard("Platform channels (${r.channels.size})") {
            r.channels.take(50).forEach { c ->
                Row(Modifier.padding(vertical = 1.dp)) {
                    Text(
                        c.name,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        c.kind,
                        fontSize = 10.sp,
                        color = if (c.kind == "app") Color(0xFFF85149)
                        else if (c.kind == "custom") Color(0xFFF0883E) else Color(0xFF8B949E),
                    )
                }
            }
        }
        CollapsibleCard("Third-party services (${r.thirdParty.size})") {
            r.thirdParty.forEach { t -> Text("· ${t.service}: ${t.evidence.joinToString(", ")}", fontSize = 11.sp) }
        }
        CollapsibleCard("Permissions (${r.permissions.size})") {
            r.permissions.forEach { p ->
                Text("· ${p.name.substringAfterLast('.')} [${p.protection}]", fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                if (p.description.isNotBlank()) Text("   ${p.description}", fontSize = 10.sp, color = Color(0xFF8B949E))
            }
        }
        if (r.deepLinks.isNotEmpty()) CollapsibleCard("Deep links (${r.deepLinks.size})") {
            r.deepLinks.take(40).forEach { Text("· ${it.scheme}://${it.host ?: "*"} → ${it.component}${if (it.autoVerify) " ✓autoVerify" else ""}", fontSize = 11.sp, fontFamily = FontFamily.Monospace) }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ActionButton("Share JSON") { share(context, r, "json") }
            ActionButton("Share Markdown") { share(context, r, "md") }
        }
        Text(
            "Generated ${DateFormat.getDateTimeInstance().format(Date(r.generatedAt))} · FlutterGuard performs static analysis of artifacts the OS makes readable to any app · authorized auditing only.",
            fontSize = 10.sp, color = Color(0xFF8B949E),
        )
        Spacer(Modifier.height(24.dp))
    }
}

private fun share(context: Context, r: Report, ext: String) {
    runCatching {
        val file = ReportExport.writeFile(context, r, ext)
        val uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = if (ext == "json") "application/json" else "text/markdown"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Share FlutterGuard report"))
    }
}

@Composable
private fun SeverityChip(label: String, count: Int, sev: Severity) {
    if (count <= 0) return
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).background(sevColor[sev] ?: Color.Gray, CircleShape))
        Spacer(Modifier.width(6.dp))
        Text("$label  $count", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun InfoCard(title: String, content: @Composable () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF161B22))) {
        Column(Modifier.padding(12.dp)) {
            Text(title, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = Color(0xFF64FFDA))
            Spacer(Modifier.height(6.dp))
            content()
        }
    }
}

@Composable
private fun InfoLine(k: String, v: String) {
    Row(Modifier.padding(vertical = 1.dp)) {
        Text(k, fontSize = 11.sp, color = Color(0xFF8B949E), modifier = Modifier.width(120.dp), maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(v, fontSize = 11.sp, fontFamily = FontFamily.Monospace, maxLines = 3, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun FindingCard(f: Finding) {
    var expanded by remember { mutableStateOf(false) }
    Card(
        modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded },
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1F26)),
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(10.dp).background(sevColor[f.severity] ?: Color.Gray, CircleShape))
                Spacer(Modifier.width(8.dp))
                Text(f.title, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, modifier = Modifier.weight(1f))
            }
            if (expanded) {
                Spacer(Modifier.height(8.dp))
                Text(f.detail, fontSize = 12.sp)
                f.evidence.take(3).forEach {
                    Text(
                        "${it.source}@${it.offset}:  ${it.snippet}",
                        fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = Color(0xFF8B949E),
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
                if (f.remediation.isNotBlank()) {
                    Spacer(Modifier.height(6.dp))
                    Icon(Icons.Default.Info, contentDescription = null, tint = Color(0xFF64B5F6), modifier = Modifier.size(14.dp))
                    Text("Fix: ${f.remediation}", fontSize = 11.sp, color = Color(0xFF64B5F6))
                }
                if (f.masvs.isNotEmpty()) Text(f.masvs.joinToString(" "), fontSize = 10.sp, color = Color(0xFF8B949E), modifier = Modifier.padding(top = 4.dp))
            }
        }
    }
}

@Composable
private fun CollapsibleCard(title: String, content: @Composable () -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded }, colors = CardDefaults.cardColors(containerColor = Color(0xFF161B22))) {
        Column(Modifier.padding(12.dp)) {
            Text(if (expanded) "▾ $title" else "▸ $title", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            if (expanded) {
                Spacer(Modifier.height(6.dp))
                content()
            }
        }
    }
}

@Composable
private fun ActionButton(label: String, onClick: () -> Unit) {
    Surface(
        color = Color(0xFF233042),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.clickable { onClick() },
    ) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(14.dp))
            Spacer(Modifier.width(6.dp))
            Text(label, fontSize = 12.sp)
        }
    }
}
