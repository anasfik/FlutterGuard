package com.flutterguard.app.ui

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.flutterguard.app.settings.ConsentPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * The bundled policy documents. The same bytes are shipped in assets/legal and
 * docs/legal (byte parity is a unit test), so the Play listing can host the
 * exact text the app renders.
 */
object LegalDocs {
    const val PRIVACY = "privacy"
    const val SECURITY = "security"

    val names = listOf(PRIVACY, SECURITY)

    fun title(doc: String): String = when (doc) {
        SECURITY -> "Security"
        else -> "Privacy policy"
    }

    /** Raw Markdown from the APK assets. Throws on a missing asset; the screen renders that visibly. */
    fun read(context: Context, doc: String): String =
        context.assets.open("legal/$doc.md").bufferedReader().use { it.readText() }

    /** Same renderer, side-loaded source: used when the text comes from a file rather than the asset. */
    fun readFile(file: File): String = file.readText()
}

/** Full-screen reader for one bundled policy document. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun LegalScreen(doc: String, onBack: () -> Unit) {
    val context = LocalContext.current
    var text by remember(doc) { mutableStateOf<String?>(null) }
    var error by remember(doc) { mutableStateOf<String?>(null) }
    LaunchedEffect(doc) {
        runCatching { withContext(Dispatchers.IO) { LegalDocs.read(context, doc) } }
            .onSuccess { text = it }
            .onFailure { error = it.message ?: "Could not read the document." }
    }
    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    navigationIcon = {
                        IconButton(onClick = onBack, modifier = Modifier.defaultMinSize(48.dp, 48.dp)) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                        }
                    },
                    title = {
                        Text(
                            LegalDocs.title(doc),
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        },
    ) { pad ->
        Surface(Modifier.padding(pad).fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            when {
                error != null -> Column(Modifier.padding(Gutter)) {
                    Text("Document unavailable", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "$error The installed copy could not be opened; the same text is published in docs/legal.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                text == null -> Column(Modifier.padding(Gutter)) {
                    Text("Reading…", style = MaterialTheme.typography.bodyMedium)
                }
                else -> MarkdownText(text!!)
            }
        }
    }
}

/**
 * First-run disclosure, shown as a dialog over the real main screen instead of a
 * wall in front of it.
 *
 * Android grants broad package visibility at install and offers no per-app
 * toggle, so [onAgree] is FlutterGuard's own gate: the second tap that says
 * "yes, list them". Dismissing is not fatal — the main screen stays up with its
 * own request action, and the file-pick path never enumerates packages.
 */
@Composable
internal fun ConsentDialog(onAgree: () -> Unit, onDecline: () -> Unit) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDecline,
        title = { Text("Allow FlutterGuard to list your apps?") },
        text = {
            Column(
                Modifier
                    .heightIn(max = 560.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(Space.m),
            ) {
                Text(
                    "Listing installed apps needs broad package visibility. Android grants it at install, so there is no system prompt to answer — this is FlutterGuard asking first.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                ConsentPoint(
                    "What it reads",
                    "The installed-app list, and the APK of any app you audit: manifest, resources, DEX and native strings, assets, signing data. Static parsing only — no app code runs.",
                )
                ConsentPoint(
                    "Why",
                    "To show which installed apps are Flutter apps and to audit their third-party surface, endpoints and embedded secrets.",
                )
                ConsentPoint(
                    "What leaves the device",
                    "Nothing. No network permission, no telemetry. Reports stay in private storage and leave only when you export one.",
                )
                ConsentPoint(
                    "Your control",
                    "Withdraw any time in Settings and the app stops listing apps. Secrets stay masked until you reveal one, and Settings can delete every stored report.",
                )
                Text(
                    "Policy version ${ConsentPolicy.POLICY_VERSION}. The full privacy policy and security model are readable in Settings.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onAgree, modifier = Modifier.defaultMinSize(minHeight = 48.dp)) {
                Text("Allow and show apps")
            }
        },
        dismissButton = {
            TextButton(onClick = onDecline, modifier = Modifier.defaultMinSize(minHeight = 48.dp)) {
                Text("Not now")
            }
        },
    )
}

@Composable
private fun ConsentPoint(title: String, body: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(Space.s)) {
        Column {
            Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            Text(body, style = MaterialTheme.typography.bodySmall)
        }
    }
}
