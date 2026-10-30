package com.flutterguard.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp

/** One display block of the small Markdown subset the legal documents use. */
sealed interface MdBlock {
    data class Heading(val level: Int, val text: String) : MdBlock
    data class Bullet(val text: String) : MdBlock
    data class Quote(val text: String) : MdBlock
    data class Paragraph(val text: String) : MdBlock
}

/** Inline run after `**bold**` and `` `code` `` are resolved. */
data class MdSpan(val text: String, val bold: Boolean = false, val code: Boolean = false)

/**
 * A deliberately small Markdown reader: headings, bullets, block quotes,
 * paragraphs, bold and inline code. That is exactly what the privacy and
 * security documents use, so a full Markdown library would be dependency weight
 * with no reader benefit. Unknown syntax stays literal text — never an error —
 * and every length is bounded so a hostile or corrupt asset cannot hang the UI.
 *
 * [parse] takes raw text so the same renderer serves a bundled asset, a
 * side-loaded file, or a future remote copy without a second code path.
 */
object Markdown {

    /** A single source line is truncated to this; documents are prose, not data. */
    const val MAX_LINE = 4000

    /** Hard cap on rendered blocks; the real documents are far below it. */
    const val MAX_BLOCKS = 2000

    private val heading = Regex("""^(#{1,6})\s+(.*)$""")
    private val bullet = Regex("""^\s*[-*+]\s+(.*)$""")
    private val quote = Regex("""^\s*>\s?(.*)$""")

    fun parse(source: String): List<MdBlock> {
        val blocks = ArrayList<MdBlock>()
        val paragraph = StringBuilder()

        fun flush() {
            if (paragraph.isNotEmpty() && blocks.size < MAX_BLOCKS) {
                blocks.add(MdBlock.Paragraph(paragraph.toString()))
            }
            paragraph.setLength(0)
        }

        for (raw in source.lineSequence()) {
            if (blocks.size >= MAX_BLOCKS) break
            val line = raw.take(MAX_LINE).trimEnd()
            val trimmed = line.trim()
            when {
                trimmed.isEmpty() -> flush()
                heading.matches(trimmed) -> {
                    flush()
                    val m = heading.find(trimmed)!!
                    blocks.add(MdBlock.Heading(m.groupValues[1].length, m.groupValues[2].trim()))
                }
                bullet.matches(trimmed) -> {
                    flush()
                    blocks.add(MdBlock.Bullet(bullet.find(trimmed)!!.groupValues[1].trim()))
                }
                quote.matches(trimmed) -> {
                    flush()
                    blocks.add(MdBlock.Quote(quote.find(trimmed)!!.groupValues[1].trim()))
                }
                else -> {
                    if (paragraph.isNotEmpty()) paragraph.append(' ')
                    paragraph.append(trimmed)
                }
            }
        }
        flush()
        return blocks
    }

    /**
     * Splits one line into styled runs. An unterminated `**` or backtick is kept
     * verbatim so odd input renders exactly as written instead of swallowing the
     * rest of the line.
     */
    fun inline(text: String): List<MdSpan> {
        val out = ArrayList<MdSpan>()
        val buffer = StringBuilder()
        var bold = false
        var code = false
        var i = 0

        fun flush() {
            if (buffer.isNotEmpty()) {
                out.add(MdSpan(buffer.toString(), bold, code))
                buffer.setLength(0)
            }
        }

        while (i < text.length) {
            val ch = text[i]
            when {
                !code && ch == '*' && i + 1 < text.length && text[i + 1] == '*' -> {
                    // Only a closed pair opens bold; an unterminated marker stays literal.
                    if (!bold && text.indexOf("**", i + 2) < 0) {
                        buffer.append("**")
                    } else {
                        flush()
                        bold = !bold
                    }
                    i += 2
                }
                ch == '`' -> {
                    if (!code && text.indexOf('`', i + 1) < 0) {
                        buffer.append('`')
                    } else {
                        flush()
                        code = !code
                    }
                    i++
                }
                else -> {
                    buffer.append(ch)
                    i++
                }
            }
        }
        flush()
        return out
    }

    /** The annotated form the Compose renderer consumes. */
    fun annotated(text: String): AnnotatedString = buildAnnotatedString {
        for (span in inline(text)) {
            if (span.bold || span.code) {
                withStyle(
                    SpanStyle(
                        fontWeight = if (span.bold) FontWeight.SemiBold else null,
                        fontFamily = if (span.code) FontFamily.Monospace else null,
                    ),
                ) { append(span.text) }
            } else {
                append(span.text)
            }
        }
    }
}

/**
 * Renders parsed blocks in a scrolling column. The whole document is one
 * LazyColumn so a long policy does not compose every paragraph at once.
 */
@Composable
internal fun MarkdownText(markdown: String, modifier: Modifier = Modifier) {
    val blocks = remember(markdown) { Markdown.parse(markdown) }
    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        contentPadding = PaddingValues(horizontal = Gutter, vertical = Space.l),
        verticalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        items(blocks) { block ->
            when (block) {
                is MdBlock.Heading -> Text(
                    Markdown.annotated(block.text),
                    style = when (block.level) {
                        1 -> MaterialTheme.typography.headlineSmall
                        2 -> MaterialTheme.typography.titleMedium
                        else -> MaterialTheme.typography.titleSmall
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = if (block.level <= 2) Space.m else Space.s)
                        .semantics { heading() },
                )
                is MdBlock.Bullet -> Row(
                    Modifier.fillMaxWidth().padding(start = Space.s),
                    verticalAlignment = Alignment.Top,
                ) {
                    Text("•", style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.width(Space.s))
                    Text(Markdown.annotated(block.text), style = MaterialTheme.typography.bodyMedium)
                }
                is MdBlock.Quote -> Column(Modifier.fillMaxWidth()) {
                    Text(
                        Markdown.annotated(block.text),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                is MdBlock.Paragraph -> Text(
                    Markdown.annotated(block.text),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}
