package com.flutterguard.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Advanced mode's one card: filters → package scan → scan-all. Everything that
 * decides enabled/blocked comes from [advancedPanelState]; this file only
 * renders it. The queue itself is a route, not a card here.
 *
 * Input radius: `MaterialTheme.shapes.extraSmall` — the one radius every input,
 * inline badge and inset field uses, so no second radius family appears here.
 */
@Composable
internal fun ToolsPanel(
    appCount: Int,
    packageInput: String,
    onPackageInput: (String) -> Unit,
    packageError: String?,
    running: Boolean,
    queueActive: Boolean,
    filter: AppFilter,
    onFilter: (AppFilter) -> Unit,
    onScanPackage: (String) -> Unit,
    onScanAll: () -> Unit,
) {
    val state = advancedPanelState(packageInput, running, queueActive, appCount, packageError)
    val focusManager = LocalFocusManager.current
    val keyboard = LocalSoftwareKeyboardController.current
    val submit: () -> Unit = {
        if (state.scanPackageEnabled) {
            keyboard?.hide()
            focusManager.clearFocus()
            onScanPackage(packageInput.trim())
        }
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(Modifier.padding(Space.l), verticalArrangement = Arrangement.spacedBy(Space.s)) {
            Text(
                "Tools",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { heading() },
            )
            ChipRow {
                WorkbenchChip(
                    selected = filter.flutterOnly,
                    onClick = { onFilter(filter.copy(flutterOnly = !filter.flutterOnly)) },
                    label = "Flutter only",
                )
                WorkbenchChip(
                    selected = filter.hideSystem,
                    onClick = { onFilter(filter.copy(hideSystem = !filter.hideSystem)) },
                    label = "Hide system",
                )
            }
            PackageScanRow(
                value = packageInput,
                onValueChange = onPackageInput,
                hint = state.packageHint,
                enabled = state.scanPackageEnabled,
                onSubmit = submit,
            )
            ScanAllRow(
                enabled = state.scanAllEnabled,
                subtitle = state.scanAllSubtitle,
                onClick = onScanAll,
            )
        }
    }
}

/**
 * A single-line inset field plus its scan action: `surface` on the card, 1 dp
 * outline, no floating label. The action is a separate 48 dp button after the
 * field with one 8 dp gap, so it reads as a button beside the field instead of
 * a hole punched into the field's trailing edge.
 */
@Composable
private fun PackageScanRow(
    value: String,
    onValueChange: (String) -> Unit,
    hint: String?,
    enabled: Boolean,
    onSubmit: () -> Unit,
) {
    var focused by remember { mutableStateOf(false) }
    val shape = MaterialTheme.shapes.extraSmall
    val outline = when {
        hint != null -> MaterialTheme.colorScheme.error
        focused -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.outlineVariant
    }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Row(
                Modifier
                    .weight(1f)
                    .defaultMinSize(minHeight = 48.dp)
                    .background(MaterialTheme.colorScheme.surface, shape)
                    .border(1.dp, outline, shape)
                    .padding(horizontal = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                BasicTextField(
                    value = value,
                    onValueChange = onValueChange,
                    modifier = Modifier
                        .weight(1f)
                        .onFocusChanged { focused = it.isFocused }
                        .semantics { contentDescription = "Package name" },
                    singleLine = true,
                    // Zero tracking: a long package id must not ellipsise before the
                    // field ends (bodyMedium ships 0.25 sp).
                    textStyle = MaterialTheme.typography.bodyMedium.copy(
                        color = MaterialTheme.colorScheme.onSurface,
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 0.sp,
                    ),
                    cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii, imeAction = ImeAction.Go),
                    keyboardActions = KeyboardActions(onGo = { onSubmit() }),
                    decorationBox = { inner ->
                        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.CenterStart) {
                            if (value.isEmpty()) {
                                Text(
                                    "com.example.app",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            inner()
                        }
                    },
                )
            }
            Spacer(Modifier.width(8.dp))
            IconButton(
                onClick = onSubmit,
                enabled = enabled,
                modifier = Modifier
                    .size(48.dp)
                    .background(
                        if (enabled) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerHigh,
                        shape,
                    ),
            ) {
                Icon(
                    Icons.Default.PlayArrow,
                    contentDescription = "Scan package",
                    tint = if (enabled) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.38f)
                    },
                    modifier = Modifier.size(16.dp),
                )
            }
        }
        hint?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
    }
}

/** A list row, not a primary button: title + reason + chevron, dimmed when blocked. */
@Composable
private fun ScanAllRow(enabled: Boolean, subtitle: String, onClick: () -> Unit) {
    val shape = MaterialTheme.shapes.medium
    Surface(
        // No cyan fill behind it: the row is a row.
        modifier = Modifier
            .fillMaxWidth()
            .clip(shape)
            // clickable(enabled = false) keeps the "disabled" semantics and blocks
            // the tap, so a blocked row cannot silently do nothing.
            .clickable(enabled = enabled, onClickLabel = "Scan all Flutter apps", onClick = onClick),
        color = MaterialTheme.colorScheme.surface,
        shape = shape,
    ) {
        Row(
            Modifier.padding(horizontal = Space.l, vertical = Space.s).defaultMinSize(minHeight = 48.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "Scan all Flutter apps",
                    style = MaterialTheme.typography.titleSmall,
                    color = if (enabled) {
                        MaterialTheme.colorScheme.onSurface
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    // Enabled: what will happen. Blocked: why it cannot, so the
                    // dimmed row is never a mystery.
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.width(8.dp))
            Icon(
                Icons.Default.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = if (enabled) 1f else 0.38f),
            )
        }
    }
}
