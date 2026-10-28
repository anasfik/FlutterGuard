package com.flutterguard.app.scan.parsers

/**
 * Minimal reader for dotenv files bundled into an APK (`assets/.env.prod` and
 * friends). The bundled file is plain text, so a few lines of parsing recover
 * exactly what the app sends to the backend — no decompilation required.
 */
object DotEnv {

    data class Entry(val name: String, val value: String)

    /** Names that hold credential material in practice. */
    private val secretName = Regex(
        "(?i)(SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|API_KEY|APP_KEY|CLIENT_ID|APP_ID|GUID|DSN|SALT|SIGNING)",
    )

    fun parse(text: String): List<Entry> {
        val out = ArrayList<Entry>()
        for (rawLine in text.lineSequence()) {
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) continue
            val eq = line.indexOf('=')
            if (eq <= 0) continue
            // Tolerate `export NAME=value` and `NAME: value` YAML-ish files.
            val name = line.substring(0, eq).trim().removePrefix("export ").trim()
            if (name.isEmpty() || !(name[0].isLetter() || name[0] == '_')) continue
            var value = line.substring(eq + 1).trim()
            val inlineComment = value.indexOf(" #")
            if (inlineComment > 0) value = value.substring(0, inlineComment).trim()
            value = value.trim('"', '\'')
            out.add(Entry(name, value))
            if (out.size >= 400) break
        }
        return out
    }

    fun isSecret(name: String): Boolean = secretName.containsMatchIn(name)
}
