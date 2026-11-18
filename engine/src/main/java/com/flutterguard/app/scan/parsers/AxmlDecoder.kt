package com.flutterguard.app.scan.parsers

import java.nio.ByteBuffer

/** Simple DOM for a decoded binary XML (AXML) document. */
class AxmlNode(val name: String) {
    val children = mutableListOf<AxmlNode>()
    val attrs = LinkedHashMap<String, String>()

    /** Character data of this element, e.g. the host inside `<domain>127.0.0.1</domain>`. */
    var text: String? = null

    fun attr(name: String): String? = attrs[name]
    fun bool(name: String): Boolean? = attrs[name]?.let { it == "true" }
    fun child(tag: String): AxmlNode? = children.firstOrNull { it.name == tag }
    fun children(tag: String): List<AxmlNode> = children.filter { it.name == tag }

    override fun toString(): String = "<$name${attrs.entries.joinToString("") { " ${it.key}=\"${it.value}\"" }}>"
}

/**
 * Decodes Android binary XML (compiled AndroidManifest.xml and res/xml entries)
 * into an [AxmlNode] tree. Attribute values are resolved to strings; resource
 * references render as "@ref/0x…".
 */
object AxmlDecoder {

    private const val TYPE_STRING_POOL = 0x0001
    private const val TYPE_XML = 0x0003
    private const val NODE_START_NS = 0x0100
    private const val NODE_END_NS = 0x0101
    private const val NODE_START = 0x0102
    private const val NODE_END = 0x0103
    private const val NODE_CDATA = 0x0104

    // Res_value data types
    private const val VAL_REFERENCE = 0x01
    private const val VAL_STRING = 0x03
    private const val VAL_INT_DEC = 0x10
    private const val VAL_INT_HEX = 0x11
    private const val VAL_INT_BOOLEAN = 0x12

    fun decode(bytes: ByteArray): AxmlNode? {
        val b = Binary.buffer(bytes)
        if (b.remaining() < 8) return null
        val rootType = Binary.u16(b)
        if (rootType != TYPE_XML) return null
        Binary.u16(b) // headerSize
        val totalSize = Binary.u32(b).toInt()
        if (totalSize <= 0 || totalSize > bytes.size) return null

        var strings: List<String> = emptyList()
        var root: AxmlNode? = null
        val stack = ArrayDeque<AxmlNode>()

        while (b.position() < totalSize && b.remaining() >= 8) {
            val chunkStart = b.position()
            val type = Binary.u16(b)
            b.short // headerSize
            val size = b.int // u32 chunk size
            when (type) {
                TYPE_STRING_POOL -> {
                    b.position(chunkStart)
                    strings = StringPool.parse(b)
                }
                NODE_START_NS, NODE_END_NS -> { /* not needed */ }
                NODE_CDATA -> {
                    // header(8) + lineNumber(4) + comment(4) then the text string index
                    b.position(chunkStart + 16)
                    val text = str(strings, b.int)
                    if (text.isNotEmpty()) {
                        val owner = stack.lastOrNull()
                        if (owner != null) owner.text = (owner.text ?: "") + text
                    }
                }
                NODE_START -> {
                    b.int // lineNumber
                    b.int // comment
                    b.int // ns ref
                    val nameIdx = b.int
                    val attributeStart = Binary.u16(b)
                    val attributeSize = Binary.u16(b)
                    val attributeCount = Binary.u16(b)
                    b.short // idIndex
                    b.short // classIndex
                    b.short // styleIndex
                    val node = AxmlNode(str(strings, nameIdx))
                    // attributes start at attrExt_start + attributeStart, where
                    // attrExt begins right after the node header (8 + 8)
                    val attrBase = chunkStart + 16 + attributeStart
                    for (i in 0 until attributeCount) {
                        b.position(attrBase + i * attributeSize)
                        b.int // attr ns
                        val attrName = str(strings, b.int)
                        val rawIdx = b.int
                        val vSize = Binary.u16(b)
                        b.get() // res0
                        val vType = b.get().toInt() and 0xFF
                        val vData = b.int
                        val value = when {
                            rawIdx != -1 -> str(strings, rawIdx)
                            else -> resolve(vType, vData, strings)
                        }
                        if (attrName.isNotEmpty()) node.attrs[attrName] = value ?: ""
                    }
                    val parent = stack.lastOrNull()
                    if (parent == null) {
                        if (root == null) root = node
                    } else parent.children.add(node)
                    stack.addLast(node)
                }
                NODE_END -> if (stack.isNotEmpty()) stack.removeLast()
            }
            if (size <= 0) break
            b.position(chunkStart + size)
        }
        return root
    }

    private fun str(pool: List<String>, idx: Int): String =
        if (idx in pool.indices) pool[idx] else ""

    private fun resolve(type: Int, data: Int, pool: List<String>): String? = when (type) {
        VAL_STRING -> str(pool, data)
        VAL_INT_BOOLEAN -> if (data != 0) "true" else "false"
        VAL_INT_DEC -> data.toString()
        VAL_INT_HEX -> "0x" + Integer.toHexString(data)
        VAL_REFERENCE -> "@ref/0x" + Integer.toHexString(data)
        else -> data.toString()
    }
}
