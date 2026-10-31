package com.flutterguard.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.flutterguard.app.scan.ReportFiles
import com.flutterguard.app.scan.ScanStore
import java.io.File
import com.flutterguard.app.settings.ConsentPolicy
import com.flutterguard.app.settings.SettingsState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import android.widget.Toast

/**
 * Settings that change real behaviour. Every toggle is read by the scanner, the
 * export dialog or the findings UI; the consent card is the same gate the
 * activity enforces before inventory runs.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsScreen(
    settings: SettingsState,
    notificationsAllowed: Boolean,
    onBack: () -> Unit,
    onChange: ((SettingsState) -> SettingsState) -> Unit,
    onOpenLegal: (String) -> Unit,
    onWithdrawConsent: () -> Unit,
    onReopenDisclosure: () -> Unit,
    /** Opens the system notification settings for this app (the only fix once denied). */
    onOpenNotificationSettings: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var confirmWithdraw by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }

    val about = remember {
        runCatching {
            val pi = context.packageManager.getPackageInfo(context.packageName, 0)
            val code = if (android.os.Build.VERSION.SDK_INT >= 28) pi.longVersionCode else pi.versionCode.toLong()
            "${pi.versionName ?: "?"} ($code)" to context.packageName
        }.getOrDefault("?" to context.packageName)
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    navigationIcon = {
                        IconButton(onClick = onBack, modifier = Modifier.size(48.dp)) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                        }
                    },
                    title = {
                        Text(
                            "Settings",
                            style = MaterialTheme.typography.titleMedium,
                            modifier = Modifier.semantics { heading() },
                        )
                    },
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        },
    ) { pad ->
        LazyColumn(
            modifier = Modifier.padding(pad).fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(Gutter),
            verticalArrangement = Arrangement.spacedBy(Space.m),
        ) {
            item { SettingsCard("Scanning") {
                ToggleRow(
                    title = "Notifications",
                    detail = if (!notificationsAllowed) {
                        "Android has blocked notifications for FlutterGuard. Scans still run; tap to enable them in system settings and be told when one finishes."
                    } else {
                        "Post the result notification when a scan finishes or fails in the background. The progress notification is required while a scan runs."
                    },
                    checked = settings.notifications && notificationsAllowed,
                    // A denied POST_NOTIFICATIONS cannot be re-requested reliably, so
                    // the row opens the system settings that can actually change it.
                    onChange = { on ->
                        if (!notificationsAllowed) onOpenNotificationSettings()
                        else onChange { it.copy(notifications = on) }
                    },
                )
                ToggleRow(
                    title = "Keep scan history",
                    detail = "Write the per-app version log (.hist) so later scans show what changed. Off: reports are still saved, the history card says it is unavailable.",
                    checked = settings.keepHistory,
                    onChange = { on -> onChange { it.copy(keepHistory = on) } },
                )
                ToggleRow(
                    title = "Scan all apps",
                    detail = "Show the scan-all queue entry point in Advanced tools. Off: the queue cannot be started from the UI; an already running queue is unaffected.",
                    checked = settings.scanAll,
                    onChange = { on -> onChange { it.copy(scanAll = on) } },
                )
                ToggleRow(
                    title = "Re-scan prompt on app update",
                    detail = "When an installed app's version differs from the stored report, the report screen offers a re-scan. This only affects the prompt: nothing scans in the background.",
                    checked = settings.rescanPrompt,
                    onChange = { on -> onChange { it.copy(rescanPrompt = on) } },
                )
            } }

            item { SettingsCard("Secrets and exports") {
                ToggleRow(
                    title = "Allow revealing secret values",
                    detail = "Off: findings keep their masked value and the Reveal action is disabled. Raw values are memory-only either way.",
                    checked = settings.revealSecrets,
                    onChange = { on -> onChange { it.copy(revealSecrets = on) } },
                )
                ToggleRow(
                    title = "Include sensitive values in exports",
                    detail = "Off: every export is redacted, whatever the export dialog asks for. On: the dialog can still require a separate per-file confirmation.",
                    checked = settings.sensitiveExport,
                    onChange = { on -> onChange { it.copy(sensitiveExport = on) } },
                )
            } }

            item {
                SettingsCard("Privacy and consent") {
                    val agreed = settings.inventoryAllowed()
                    Text(
                        if (agreed) {
                            "Installed-app scanning is on, agreed to policy version ${settings.consentVersion}."
                        } else {
                            "Installed-app scanning is off. Only APK files you pick or share can be audited."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = if (agreed) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
                    )
                    // Declining once must not be a trap: the only route back to the
                    // disclosure is this row, and the policy text itself cannot grant
                    // consent. Withdrawing resets to the same place.
                    if (agreed) {
                        LinkRow("Withdraw consent", "stops installed-app inventory and shows the disclosure again") {
                            confirmWithdraw = true
                        }
                    } else {
                        LinkRow("Review disclosure and choose again", "reopens the consent screen") {
                            onReopenDisclosure()
                        }
                    }
                }
            }

            item { SettingsCard("Legal") {
                LinkRow("Privacy policy", "what is read, stored and deleted") { onOpenLegal(LegalDocs.PRIVACY) }
                LinkRow("Security model", "boundaries, secret handling and limitations") { onOpenLegal(LegalDocs.SECURITY) }
            } }

            item { SettingsCard("About") {
                InfoRow("Version", about.first)
                InfoRow("Package", about.second)
                InfoRow("Policy version", ConsentPolicy.POLICY_VERSION.toString())
                Text(
                    "FlutterGuard has no network permission and no telemetry. Reports stay in this app's own storage.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } }

            item { SettingsCard("Data") {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .defaultMinSize(minHeight = 48.dp)
                        .clickable(onClickLabel = "Delete all reports") { confirmDelete = true },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Delete all reports", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.error)
                        Text(
                            "Removes every stored report, history log and interrupted-scan marker from this app's storage.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            } }
        }
    }

    if (confirmWithdraw) {
        AlertDialog(
            onDismissRequest = { confirmWithdraw = false },
            title = { Text("Withdraw privacy consent?") },
            text = {
                Text(
                    "Installed-app inventory stops immediately and the disclosure is shown again. Stored reports are kept; you can delete them separately. File-pick scans keep working.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmWithdraw = false
                    onWithdrawConsent()
                }) { Text("Withdraw") }
            },
            dismissButton = { TextButton(onClick = { confirmWithdraw = false }) { Text("Cancel") } },
        )
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete all reports?") },
            text = {
                Text(
                    "This deletes every report, history log, in-flight marker and cached export copy. It cannot be undone, and copies you already shared with another app are not affected.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    scope.launch {
                        val removed = withContext(Dispatchers.IO) {
                            val reports = ReportFiles.deleteAll(ReportFiles.appDir(context))
                            // A sensitive export is written to cache/exports before it is
                            // shared; deleting reports must not leave those raw values behind.
                            val exports = File(context.cacheDir, "exports")
                            val shared = exports.listFiles()?.size ?: 0
                            exports.deleteRecursively()
                            reports + shared
                        }
                        // reset() is a test hook that nulls the executing job, which would
                        // admit a second scanner and let the live scan write its report back
                        // after this delete. Never touch a running scan from here.
                        if (!ScanStore.isExecuting()) ScanStore.reset()
                        Toast.makeText(
                            context,
                            if (removed == 0) "No stored reports to delete." else "Deleted $removed stored file(s).",
                            Toast.LENGTH_LONG,
                        ).show()
                    }
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun SettingsCard(title: String, content: @Composable () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(Modifier.padding(Space.l), verticalArrangement = Arrangement.spacedBy(Space.s)) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { heading() },
            )
            content()
        }
    }
}

/** One row per preference: the row owns the tap, the switch renders the state. */
@Composable
private fun ToggleRow(
    title: String,
    detail: String,
    checked: Boolean,
    enabled: Boolean = true,
    onChange: (Boolean) -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .defaultMinSize(minHeight = 48.dp)
            .clickable(enabled = enabled, role = Role.Switch) { onChange(!checked) },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.width(Space.s))
        Switch(checked = checked, onCheckedChange = null, enabled = enabled)
    }
}

@Composable
private fun LinkRow(title: String, detail: String, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .defaultMinSize(minHeight = 48.dp)
            .clickable(onClickLabel = title, onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Icon(Icons.Default.KeyboardArrowRight, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().defaultMinSize(minHeight = 32.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}
