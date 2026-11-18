package com.flutterguard.app.scan

/**
 * What a finding proves, not how exploitable the app is.
 *
 * This classification is deliberately conservative: it is the difference
 * between reading configuration out of the artifact and matching a string in
 * it. It is never a verdict on runtime behaviour or exploitability.
 */
enum class FindingKind {
    /**
     * Directly observed artifact configuration or material: a decoded manifest
     * flag/component, a decoded network-security policy, the signer certificate,
     * a bundled Flutter/Dart entry. Says nothing about whether the app is
     * exploitable, whether a device is affected, or whether a credential works.
     */
    CONFIRMED,

    /**
     * A lead worth checking: a string or shape in the artifact (credential
     * patterns, WebView/Dart API markers, HTTP references, filename/extension
     * signals, obfuscation counts). Presence is a hypothesis about reachable
     * code, not proof of use.
     */
    SUSPECTED,

    /** Inventory or public identifiers: addresses, names, hashes, file lists. */
    INFORMATIONAL,
    ;

    /**
     * Certainty rank: lower is more certain. A serialized kind may never be more
     * certain than the catalog kind for the same ID.
     */
    val certainty: Int get() = ordinal

    companion object {
        /** The less certain of two kinds (`CONFIRMED` > `SUSPECTED` > `INFORMATIONAL`). */
        fun lessCertain(a: FindingKind, b: FindingKind): FindingKind = if (a.ordinal >= b.ordinal) a else b

        /** Parses a serialized kind; null for anything this build does not know. */
        fun parse(raw: String?): FindingKind? = entries.firstOrNull { it.name == raw }
    }
}

/**
 * The one place a rule ID's [FindingKind] is decided.
 *
 * Every literal ID the scanner can emit is listed here, including the
 * generated `MAN-EXPORTED-*`, `WEB-*` and `FLUT-TLS-*` families. An ID that is
 * not listed — a typo, an empty decoded ID, a rule added by a future build —
 * resolves to [FindingKind.SUSPECTED]; missing coverage can never upgrade a
 * finding to a confirmed fact.
 *
 * Rationale per family lives in `docs/superpowers/plans/confidence-audit.md`.
 */
object FindingCatalog {

    private val kinds: Map<String, FindingKind> = linkedMapOf(
        // ---- decoded manifest / signing / network / Flutter facts -------------
        "MAN-DEBUG" to FindingKind.CONFIRMED,
        "MAN-TESTONLY" to FindingKind.CONFIRMED,
        "MAN-BACKUP" to FindingKind.CONFIRMED,
        "MAN-CLEARTEXT" to FindingKind.CONFIRMED,
        "MAN-SHAREDUID" to FindingKind.CONFIRMED,
        "MAN-CUSTOMPERM" to FindingKind.CONFIRMED,
        "MAN-EXPORTED-activity" to FindingKind.CONFIRMED,
        "MAN-EXPORTED-service" to FindingKind.CONFIRMED,
        "MAN-EXPORTED-receiver" to FindingKind.CONFIRMED,
        "MAN-EXPORTED-provider" to FindingKind.CONFIRMED,
        "MAN-DEEPLINK" to FindingKind.CONFIRMED,
        "NET-CLEARTEXT-DEFAULT" to FindingKind.CONFIRMED,
        "NET-CLEARTEXT" to FindingKind.CONFIRMED,
        "NET-DEBUG-OVERRIDES" to FindingKind.CONFIRMED,
        "NET-USERCA" to FindingKind.CONFIRMED,
        "NET-PINS" to FindingKind.CONFIRMED,
        // Certificate subject as read by the platform adapter. Not a chain or
        // trust validation.
        "SIG-DEBUG" to FindingKind.CONFIRMED,
        "FLUT-DEBUG-BUILD" to FindingKind.CONFIRMED,
        "FLUT-JIT-SNAPSHOT" to FindingKind.CONFIRMED,
        "FLUT-DEBUG-ENGINE" to FindingKind.CONFIRMED,
        "FLUT-NO-AOT" to FindingKind.CONFIRMED,

        // ---- decoded facts with no severity story: inventory only ------------
        "NET-NSC-UNRESOLVED" to FindingKind.INFORMATIONAL,
        "FLUT-NO-ARM64" to FindingKind.INFORMATIONAL,
        "FLUT-FINGERPRINT" to FindingKind.INFORMATIONAL,
        "FLUT-NOTICES" to FindingKind.INFORMATIONAL,
        "FLUT-PUBSPEC" to FindingKind.INFORMATIONAL,
        "WEB-PAYLOAD" to FindingKind.INFORMATIONAL,
        "SDK-MARKER" to FindingKind.INFORMATIONAL,
        "AST-CONFIG" to FindingKind.INFORMATIONAL,
        "AST-FIREBASE-JSON" to FindingKind.INFORMATIONAL,
        "CRYPTO-X509" to FindingKind.INFORMATIONAL,
        "FLUT-JNI-SURFACE" to FindingKind.INFORMATIONAL,

        // ---- leads: string presence, not behaviour ---------------------------
        // A v1-only signature is a scheme-presence read whose failure mode looks
        // like "no v2 block"; never a confirmed signing fact.
        "SIG-V1-ONLY" to FindingKind.SUSPECTED,
        "NET-HTTP-HOSTS" to FindingKind.SUSPECTED,
        "FLUT-NO-OBFUSCATION" to FindingKind.SUSPECTED,
        "WEB-addJavascriptInterface" to FindingKind.SUSPECTED,
        "WEB-setAllowFileAccessFromFileURLs" to FindingKind.SUSPECTED,
        "WEB-setAllowUniversalAccessFromFileURLs" to FindingKind.SUSPECTED,
        "WEB-setWebContentsDebuggingEnabled" to FindingKind.SUSPECTED,
        "WEB-setJavaScriptEnabled" to FindingKind.SUSPECTED,
        "WEB-onReceivedSslError" to FindingKind.SUSPECTED,
        "WEB-JavascriptInterface" to FindingKind.SUSPECTED,
        "WEB-loadDataWithBaseURL" to FindingKind.SUSPECTED,
        "FLUT-CHANNELS" to FindingKind.SUSPECTED,
        "FLUT-TLS-badCertificateCallback" to FindingKind.SUSPECTED,
        "FLUT-TLS-setTrustedCertificates" to FindingKind.SUSPECTED,
        "FLUT-PROXY-APP" to FindingKind.SUSPECTED,
        "SEC-PRIVATE-KEY" to FindingKind.SUSPECTED,
        "NET-PIN-MATERIAL" to FindingKind.SUSPECTED,
        "FLUT-NATIVE-BRIDGE" to FindingKind.SUSPECTED,
        // Extension-only signals; a .pem may be a public certificate.
        "AST-KEYMATERIAL" to FindingKind.SUSPECTED,
        "AST-KEYFILE" to FindingKind.SUSPECTED,
        "AST-DOTENV" to FindingKind.SUSPECTED,
        "AST-ENV" to FindingKind.SUSPECTED,
        // Credential shapes: a matching string does not prove a live credential.
        "SEC-KEY-PRIVATE" to FindingKind.SUSPECTED,
        "SEC-KEY-STRIPE-SECRET" to FindingKind.SUSPECTED,
        "SEC-KEY-AWS" to FindingKind.SUSPECTED,
        "SEC-KEY-AWS-SECRET" to FindingKind.SUSPECTED,
        "SEC-KEY-GOOGLE" to FindingKind.SUSPECTED,
        "SEC-KEY-GITHUB" to FindingKind.SUSPECTED,
        "SEC-KEY-SLACK" to FindingKind.SUSPECTED,
        "SEC-KEY-OPENAI" to FindingKind.SUSPECTED,
        "SEC-KEY-SENDGRID" to FindingKind.SUSPECTED,
        "SEC-KEY-TELEGRAM" to FindingKind.SUSPECTED,
        "SEC-KEY-GENERIC" to FindingKind.SUSPECTED,
        "SEC-KEY-JWT" to FindingKind.SUSPECTED,
        "SEC-KEY-SUPABASE-SECRET" to FindingKind.SUSPECTED,
        "SEC-DB-URI" to FindingKind.SUSPECTED,
        "SEC-BASIC-AUTH-URL" to FindingKind.SUSPECTED,
        "SEC-KEY-ANTHROPIC" to FindingKind.SUSPECTED,
        "SEC-KEY-OPENAI-PROJECT" to FindingKind.SUSPECTED,
        "SEC-KEY-GROQ" to FindingKind.SUSPECTED,
        "SEC-KEY-HUGGINGFACE" to FindingKind.SUSPECTED,
        "SEC-KEY-REPLICATE" to FindingKind.SUSPECTED,
        "SEC-KEY-OPENROUTER" to FindingKind.SUSPECTED,
        "SEC-KEY-XAI" to FindingKind.SUSPECTED,
        "SEC-KEY-FIREWORKS" to FindingKind.SUSPECTED,
        "SEC-WEBHOOK-SLACK" to FindingKind.SUSPECTED,
        "SEC-WEBHOOK-DISCORD" to FindingKind.SUSPECTED,
        "SEC-KEY-POSTMARK" to FindingKind.SUSPECTED,
        "SEC-KEY-MAILGUN" to FindingKind.SUSPECTED,
        "SEC-GCP-SERVICE-ACCOUNT" to FindingKind.SUSPECTED,
        "SEC-AZURE-ACCOUNT-KEY" to FindingKind.SUSPECTED,
        "SEC-KEY-DIGITALOCEAN" to FindingKind.SUSPECTED,
        "SEC-KEY-GITHUB-PAT" to FindingKind.SUSPECTED,
        "SEC-KEY-GITLAB" to FindingKind.SUSPECTED,
        "SEC-KEY-NPM" to FindingKind.SUSPECTED,
        "SEC-KEY-POSTMAN" to FindingKind.SUSPECTED,
        "SEC-KEY-DOCKER" to FindingKind.SUSPECTED,
        "SEC-KEY-AIRTABLE" to FindingKind.SUSPECTED,
        "SEC-KEY-NOTION" to FindingKind.SUSPECTED,
        "SEC-KEY-LINEAR" to FindingKind.SUSPECTED,
        "SEC-BEARER-JWT" to FindingKind.SUSPECTED,
        "SEC-CRYPTO-ECB" to FindingKind.SUSPECTED,

        // ---- public identifiers by design ------------------------------------
        "SEC-ENV-KEY" to FindingKind.INFORMATIONAL,
        "SEC-SUPABASE-PUBLISHABLE" to FindingKind.INFORMATIONAL,
        "SEC-KEY-OAUTH-CLIENT" to FindingKind.INFORMATIONAL,
        "SEC-FIREBASE" to FindingKind.INFORMATIONAL,
        "SEC-SENTRY-DSN" to FindingKind.INFORMATIONAL,
        "SEC-MAPBOX" to FindingKind.INFORMATIONAL,
        "SEC-REVENUECAT" to FindingKind.INFORMATIONAL,
        "SEC-SUPABASE" to FindingKind.INFORMATIONAL,
    )

    /** Every literal ID the scanner can emit (102 at the W1 audit). */
    val knownIds: Set<String> get() = kinds.keys

    /** Kind for one rule ID; unknown, empty and future IDs are never CONFIRMED. */
    fun kindOf(id: String): FindingKind = kinds[id] ?: FindingKind.SUSPECTED

    /**
     * Kind for one finding. The catalog kind applies, except that the INFO
     * branch of a multi-severity rule is inventory: a loopback-only cleartext
     * policy or a SHA-256 pin set is reported (`NET-CLEARTEXT`, `NET-PINS`) but
     * must not be graded just because the same ID has a serious branch. No
     * other severity changes a kind.
     */
    fun kindOf(id: String, severity: Severity): FindingKind {
        val catalog = kindOf(id)
        return if (catalog == FindingKind.CONFIRMED && severity == Severity.INFO) {
            FindingKind.INFORMATIONAL
        } else {
            catalog
        }
    }
}
