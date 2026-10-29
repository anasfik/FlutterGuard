package com.flutterguard.app.ui

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ClipDescription
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PersistableBundle
import android.view.Window
import android.view.WindowManager
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogWindowProvider
import androidx.core.content.FileProvider
import com.flutterguard.app.scan.Severity
import java.io.File
import java.text.DateFormat
import java.util.Date

/**
 * One spacing scale. Every padding, gap and inset in this UI is one of these
 * steps; there is no 2/6/10/14/18/20 dp between them.
 */
object Space {
    val xs = 4.dp
    val s = 8.dp
    val m = 12.dp
    val l = 16.dp
    val xl = 24.dp
    val xxl = 32.dp
}

/** One horizontal gutter for header, search, chips, state rows and lists. */
val Gutter = Space.l

/** Accessible role of a segment; never a checkbox (that is the F3 defect). */
enum class SegmentRole { TAB, CHECKBOX }

/**
 * Chip sizing, in dp. One place so the pill cannot quietly grow back into a
 * 48 dp bar and the target cannot shrink below the accessible minimum.
 */
object ChipMetrics {
    /** Touch target, not the visual pill. */
    const val TOUCH_DP = 48

    /** Visual pill height; the target above stays 48. */
    const val PILL_DP = 32
    const val PAD_H_DP = 12
    const val PAD_V_DP = 4
    const val ICON_DP = 16
    const val GAP_DP = 8
}

data class SegmentSemantics(
    val label: String,
    val selected: Boolean,
    val stateDescription: String,
    val role: SegmentRole,
) {
    /** What TalkBack reads for the single merged node: the label exactly once. */
    val announcement: String get() = label
}

/**
 * Resolves the one semantics node a segment must emit: a label, a selected
 * state and a tab role. The device dump showed an empty CheckBox node plus a
 * loose TextView per segment, so the label/state/role are resolved here instead
 * of being inherited from a Material component's internal checkbox semantics.
 */
object Segments {
    const val FALLBACK_LABEL = "Section"

    fun of(label: String, selected: Boolean): SegmentSemantics {
        val resolved = label.trim().ifEmpty { FALLBACK_LABEL }
        return SegmentSemantics(
            label = resolved,
            selected = selected,
            stateDescription = if (selected) "Selected" else "Not selected",
            role = SegmentRole.TAB,
        )
    }
}

/**
 * Segmented/workbench chip: one merged, labeled selectable node (tab role,
 * selected state), a single accent (cyan).
 *
 * Compact form: a 32–36 dp pill inside a real 48 dp touch target. The visual
 * pill is a fixed-ish height so a row of chips is one calm line; the target
 * around it is the accessible size. Selected state is carried by the container
 * plus a check icon, never by colour alone.
 */
@Composable
fun WorkbenchChip(selected: Boolean, onClick: () -> Unit, label: String) {
    val segment = remember(label, selected) { Segments.of(label, selected) }
    Box(
        modifier = Modifier
            // 48 dp target. A Box relaxes the min constraints it passes to its
            // child, so the pill below keeps its own compact height.
            .heightIn(min = ChipMetrics.TOUCH_DP.dp)
            // One labeled node: click action + tab role + an explicit state
            // description. No checkbox role, no second empty semantics node.
            .clickable(role = Role.Tab, onClick = onClick)
            .semantics(mergeDescendants = true) {
                stateDescription = segment.stateDescription
            },
        contentAlignment = Alignment.Center,
    ) {
        Surface(
            shape = MaterialTheme.shapes.extraLarge,
            color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainer,
            contentColor = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface,
            border = BorderStroke(
                1.dp,
                if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
            ),
            modifier = Modifier.heightIn(min = ChipMetrics.PILL_DP.dp),
        ) {
            Row(
                Modifier.padding(horizontal = ChipMetrics.PAD_H_DP.dp, vertical = ChipMetrics.PAD_V_DP.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (selected) {
                    Icon(
                        Icons.Default.Check,
                        contentDescription = null,
                        modifier = Modifier.size(ChipMetrics.ICON_DP.dp),
                    )
                    Spacer(Modifier.width(ChipMetrics.GAP_DP.dp))
                }
                Text(
                    segment.label,
                    style = MaterialTheme.typography.labelLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

/**
 * One row of chips: a single line that scrolls horizontally instead of wrapping
 * to a second line at large font scales. Each chip keeps its own tap target and
 * tab role; the scroll is a sibling gesture, not a replacement for the tap.
 */
@Composable
fun ChipRow(modifier: Modifier = Modifier, content: @Composable RowScope.() -> Unit) {
    Row(
        modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(Space.s),
        verticalAlignment = Alignment.CenterVertically,
        content = content,
    )
}

/**
 * Colour roles for one severity, taken from the scheme so light and dark stay
 * legible without a second palette. Two hues only — `error` and neutral — and
 * four emphasis steps; ordering is carried by the list sort and the severity
 * word, never by hue alone.
 */
data class SeverityStyle(val dot: Color, val container: Color, val content: Color, val stroke: Color?)

@Composable
fun severityStyle(severity: Severity): SeverityStyle {
    val scheme = MaterialTheme.colorScheme
    return when (severity) {
        Severity.CRITICAL -> SeverityStyle(scheme.error, scheme.errorContainer, scheme.onErrorContainer, null)
        // Outlined: the same red family one emphasis step down from CRITICAL.
        Severity.HIGH -> SeverityStyle(scheme.error, scheme.surfaceContainerHigh, scheme.error, scheme.error)
        Severity.MEDIUM -> SeverityStyle(scheme.onSurfaceVariant, scheme.surfaceContainerHigh, scheme.onSurface, null)
        Severity.LOW, Severity.INFO ->
            SeverityStyle(scheme.outline, scheme.surfaceContainerHigh, scheme.onSurfaceVariant, null)
    }
}

@Composable
fun SeverityDot(severity: Severity, size: Int = 8) {
    Surface(color = severityStyle(severity).dot, shape = CircleShape, modifier = Modifier.size(size.dp)) {}
}

@Composable
fun Banner(title: String, detail: String, error: Boolean = false) {
    Card(
        Modifier.fillMaxWidth().padding(horizontal = Gutter, vertical = Space.xs),
        colors = CardDefaults.cardColors(
            containerColor = if (error) MaterialTheme.colorScheme.errorContainer
            else MaterialTheme.colorScheme.surfaceContainerHigh,
        ),
    ) {
        Row(Modifier.padding(Space.l), verticalAlignment = Alignment.Top) {
            Icon(
                if (error) Icons.Default.Warning else Icons.Default.Info,
                contentDescription = null,
                tint = if (error) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(16.dp),
            )
            Spacer(Modifier.width(Space.s))
            Column {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    color = if (error) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (error) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(Space.l)) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { heading() },
            )
            Spacer(Modifier.height(Space.s))
            content()
        }
    }
}

/** Share of the row the key column gets; a fixed dp width wrapped real mono names. */
private const val KEY_WEIGHT = 0.4f

/**
 * One metadata row: key and value share the width by ratio, so a long mono name
 * wraps instead of being clipped by a magic 124 dp column.
 *
 * [copyable] is for values whose whole content is the evidence — hashes and
 * fingerprints. Those never truncate: the value wraps in full and carries a
 * "Copy" action labelled with its key, because a hash you cannot copy has no
 * research use.
 */
@Composable
fun InfoLine(key: String, value: String, mono: Boolean = true, copyable: Boolean = false) {
    val context = LocalContext.current
    Row(Modifier.fillMaxWidth().padding(vertical = Space.xs), verticalAlignment = Alignment.Top) {
        Text(
            key,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(KEY_WEIGHT),
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Column(Modifier.weight(1f - KEY_WEIGHT).padding(start = Space.s)) {
            Text(
                value,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
                maxLines = if (copyable) Int.MAX_VALUE else 4,
                overflow = if (copyable) TextOverflow.Clip else TextOverflow.Ellipsis,
            )
            if (copyable && value != ReportMetadata.UNAVAILABLE) {
                TextAction("Copy", onClick = { copyText(context, value, "Copied") }, contentDescription = "Copy $key")
            }
        }
    }
}

@Composable
fun ActionButton(
    label: String,
    icon: ImageVector,
    onClick: () -> Unit,
    enabled: Boolean = true,
) {
    androidx.compose.material3.Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.defaultMinSize(minHeight = 48.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        ),
        shape = MaterialTheme.shapes.extraLarge,
    ) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(Space.s))
        Text(label)
    }
}

@Composable
fun TextAction(label: String, onClick: () -> Unit, enabled: Boolean = true, contentDescription: String? = null) {
    TextButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier
            .defaultMinSize(minHeight = 48.dp)
            .then(
                if (contentDescription == null) Modifier
                else Modifier.semantics { this.contentDescription = contentDescription },
            ),
    ) {
        Text(label)
    }
}

@Composable
fun EmptyState(title: String, detail: String, actionLabel: String? = null, onAction: (() -> Unit)? = null) {
    Column(
        Modifier.fillMaxWidth().padding(Gutter),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        horizontalAlignment = Alignment.Start,
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Text(detail, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (actionLabel != null && onAction != null) {
            ActionButton(actionLabel, Icons.Default.Info, onAction)
        }
    }
}

fun formatTimestamp(ms: Long): String =
    DateFormat.getDateTimeInstance().format(Date(ms))

/** Explicit external navigation only; missing handlers are shown, never silent. */
fun openWebLink(context: Context, raw: String?) {
    val url = safeWebUrl(raw)
    if (url == null) {
        Toast.makeText(context, "Only http/https links can be opened.", Toast.LENGTH_SHORT).show()
        return
    }
    try {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    } catch (_: ActivityNotFoundException) {
        Toast.makeText(context, "No app can open this link.", Toast.LENGTH_SHORT).show()
    } catch (_: SecurityException) {
        Toast.makeText(context, "This link was blocked by the system.", Toast.LENGTH_SHORT).show()
    }
}

/**
 * Copy helper. [sensitive] marks the clip as sensitive on API 33+, so the
 * clipboard preview does not show a revealed secret or raw artifact text.
 */
fun copyText(context: Context, text: String, label: String = "Copied", sensitive: Boolean = false) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? android.content.ClipboardManager ?: return
    runCatching {
        val clip = android.content.ClipData.newPlainText("FlutterGuard", text)
        if (sensitive && Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        cm.setPrimaryClip(clip)
    }
        .onSuccess { Toast.makeText(context, label, Toast.LENGTH_SHORT).show() }
        .onFailure { Toast.makeText(context, "Copy failed", Toast.LENGTH_SHORT).show() }
}

/**
 * Window protection for on-screen secrets. Acquired only while a revealed value
 * or a raw preview is visible. Counted per window: a revealed secret on the
 * activity's window and a raw artifact preview in a Dialog are different
 * windows, so hiding one must not clear the other's flag. `FLAG_SECURE` is a
 * per-window flag — setting it on the Activity window does not protect a Dialog,
 * which is why a dialog needs this itself.
 */
object ScreenProtection {
    private val holders = HashMap<Window, Int>()

    fun acquire(window: Window) {
        holders[window] = (holders[window] ?: 0) + 1
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    fun release(window: Window) {
        val left = (holders[window] ?: 1) - 1
        if (left > 0) {
            holders[window] = left
            return
        }
        holders.remove(window)
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}

/**
 * Protects the window this composable is actually rendered into: a Dialog hosts
 * its content in a [DialogWindowProvider], so call this *inside* the dialog
 * content to cover the dialog, and anywhere else for the activity window.
 */
@Composable
fun SecureScreen(active: Boolean) {
    val view = LocalView.current
    val window = remember(view) {
        (view as? DialogWindowProvider)?.window
            ?: (view.parent as? DialogWindowProvider)?.window
            ?: view.context.findActivity()?.window
    }
    DisposableEffect(active, window) {
        if (active && window != null) ScreenProtection.acquire(window)
        onDispose { if (active && window != null) ScreenProtection.release(window) }
    }
}

private fun Context.findActivity(): Activity? {
    var current: Context? = this
    while (current is ContextWrapper) {
        if (current is Activity) return current
        current = current.baseContext
    }
    return null
}

/** Share an already-written report file; failures are user-visible. */
fun shareReportFile(context: Context, file: File, ext: String) {
    runCatching {
        val uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = if (ext == "json") "application/json" else "text/markdown"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Share FlutterGuard report"))
    }.onFailure {
        Toast.makeText(context, "Could not share the export: ${it.message ?: "unknown error"}", Toast.LENGTH_LONG).show()
    }
}
