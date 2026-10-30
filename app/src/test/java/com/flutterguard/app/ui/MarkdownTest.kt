package com.flutterguard.app.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The hand-written Markdown subset: headings, bullets, quotes, paragraphs, bold, code. */
class MarkdownTest {

    @Test
    fun headingsKeepTheirLevelAndText() {
        val blocks = Markdown.parse("# One\n\n### Three")
        assertEquals(listOf(MdBlock.Heading(1, "One"), MdBlock.Heading(3, "Three")), blocks)
    }

    @Test
    fun hashesWithoutTextOrSpaceAreLiteralParagraphs() {
        val blocks = Markdown.parse("####\n#notaheading")
        assertEquals(1, blocks.size)
        assertEquals(MdBlock.Paragraph("#### #notaheading"), blocks[0])
    }

    @Test
    fun bulletsAreTheirOwnBlocksAndConsecutiveOnesDoNotMerge() {
        val blocks = Markdown.parse("- first\n* second\n+ third")
        assertEquals(
            listOf(MdBlock.Bullet("first"), MdBlock.Bullet("second"), MdBlock.Bullet("third")),
            blocks,
        )
    }

    @Test
    fun paragraphsJoinWrappedLinesAndSplitOnBlankLines() {
        val blocks = Markdown.parse("first line\nsecond line\n\nnext paragraph")
        assertEquals(
            listOf(MdBlock.Paragraph("first line second line"), MdBlock.Paragraph("next paragraph")),
            blocks,
        )
    }

    @Test
    fun quotesAreSeparateBlocks() {
        val blocks = Markdown.parse("> quoted policy text")
        assertEquals(listOf(MdBlock.Quote("quoted policy text")), blocks)
    }

    @Test
    fun inlineBoldAndCodeAreSplitIntoRuns() {
        val spans = Markdown.inline("A **bold** and `code` end")
        assertEquals(
            listOf(
                MdSpan("A "),
                MdSpan("bold", bold = true),
                MdSpan(" and "),
                MdSpan("code", code = true),
                MdSpan(" end"),
            ),
            spans,
        )
    }

    @Test
    fun unterminatedMarkersStayLiteral() {
        assertEquals(listOf(MdSpan("unclosed **bold")), Markdown.inline("unclosed **bold"))
        assertEquals(listOf(MdSpan("unclosed `code")), Markdown.inline("unclosed `code"))
    }

    @Test
    fun emptyAndWhitespaceInputProduceNoBlocks() {
        assertEquals(emptyList<MdBlock>(), Markdown.parse(""))
        assertEquals(emptyList<MdBlock>(), Markdown.parse("\n\n   \n\t\n"))
    }

    @Test
    fun oddInputIsBoundedNotACrash() {
        val huge = "x".repeat(Markdown.MAX_LINE * 2 + 10)
        val blocks = Markdown.parse(huge)
        assertEquals(1, blocks.size)
        val text = (blocks[0] as MdBlock.Paragraph).text
        assertEquals(Markdown.MAX_LINE, text.length)

        val many = (1..Markdown.MAX_BLOCKS + 50).joinToString("\n\n") { "p$it" }
        assertEquals(Markdown.MAX_BLOCKS, Markdown.parse(many).size)
    }

    @Test
    fun annotatedTextFlattensBackToTheSameCharacters() {
        val source = "Read **this** and `that`."
        assertEquals("Read this and that.", Markdown.annotated(source).text)
        assertTrue(Markdown.annotated(source).spanStyles.isNotEmpty())
    }
}
