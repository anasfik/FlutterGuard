package com.flutterguard.app.scan.parsers

/**
 * Reads the subject of a base64 (DER) certificate found in the string layer.
 * Enough to say "this artifact pins/trusts this identity" without a full ASN.1
 * parser: we only need the CN (OID 2.5.4.3) and O (2.5.4.10) values.
 */
object X509 {

    private val CN = byteArrayOf(0x06, 0x03, 0x55, 0x04, 0x03)
    private val O = byteArrayOf(0x06, 0x03, 0x55, 0x04, 0x0A)

    /** Returns e.g. `CN=Omar Hatem · O=Cake Wallet`, or null when this is not a certificate. */
    fun subject(b64: String): String? {
        val der = runCatching { java.util.Base64.getMimeDecoder().decode(b64) }.getOrNull() ?: return null
        if (der.size < 120 || der[0] != 0x30.toByte()) return null
        val cn = value(der, CN)
        val o = value(der, O)
        if (cn == null && o == null) return null
        return listOfNotNull(cn?.let { "CN=$it" }, o?.let { "O=$it" }).joinToString(" · ")
    }

    private fun value(der: ByteArray, oid: ByteArray): String? {
        // issuer DN precedes subject DN in a TBSCertificate, so the *last* hit is the subject.
        val i = lastIndexOf(der, oid) ?: return null
        var p = i + oid.size
        // Skip the enclosing SET, then find the string tag.
        while (p < der.size - 2 && p < i + oid.size + 12) {
            val tag = der[p].toInt() and 0xFF
            if (tag in 0x0C..0x1E && tag != 0x11 && tag != 0x12 && tag != 0x13 && tag != 0x1D) {
                p++
                continue
            }
            if (tag == 0x0C || tag == 0x13 || tag == 0x16 || tag == 0x14) {
                var len = der[p + 1].toInt() and 0xFF
                var start = p + 2
                if (len and 0x80 != 0) {
                    val n = len and 0x7F
                    if (n !in 1..2) return null
                    var v = 0
                    for (k in 0 until n) v = (v shl 8) or (der[start + k].toInt() and 0xFF)
                    start += n
                    len = v
                }
                if (len !in 1..128 || start + len > der.size) return null
                return String(der, start, len, Charsets.UTF_8).trim()
            }
            p++
        }
        return null
    }

    private fun lastIndexOf(hay: ByteArray, needle: ByteArray): Int? {
        outer@ for (i in hay.size - needle.size downTo 0) {
            for (j in needle.indices) if (hay[i + j] != needle[j]) continue@outer
            return i
        }
        return null
    }
}
