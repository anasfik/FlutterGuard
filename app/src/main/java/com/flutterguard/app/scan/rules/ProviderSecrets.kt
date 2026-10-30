package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.Severity

/**
 * Key formats the corpus actually carries, grouped apart from
 * `SecretScanner.buildRules()` so that file stays about the Flutter artifact
 * itself and this one stays about provider credentials.
 *
 * Every rule is gated by a cheap literal that must appear somewhere in the
 * same 64 KB window, so the expensive regex only runs on plausible strings.
 * The gates are also what keep a bare `secret_` from matching prose.
 */
object ProviderSecrets {

    val rules: List<SecretRule> = listOf(

        // ---- AI providers --------------------------------------------------
        // A leaked model key is a billing incident and, for the providers with
        // organisation-level keys, a data-access incident.
        SecretRule(
            "SEC-KEY-ANTHROPIC", "Hardcoded Anthropic API key", Severity.CRITICAL,
            gates = listOf("sk-ant-"),
            regex = Regex("""sk-ant-[A-Za-z0-9_\-]{20,140}"""),
            remediation = "Revoke the key in the Anthropic console; proxy model calls through your backend.",
            masvs = listOf("MASVS-NETWORK-2", "MASVS-CODE-4"),
        ),
        SecretRule(
            "SEC-KEY-OPENAI-PROJECT", "Hardcoded OpenAI project key", Severity.CRITICAL,
            gates = listOf("sk-proj-"),
            regex = Regex("""sk-proj-[A-Za-z0-9_\-]{20,200}"""),
            remediation = "Revoke the key; OpenAI project keys carry spend and resource scope.",
            masvs = listOf("MASVS-NETWORK-2", "MASVS-CODE-4"),
        ),
        SecretRule(
            "SEC-KEY-GROQ", "Hardcoded Groq API key", Severity.HIGH,
            gates = listOf("gsk_"),
            regex = Regex("""\bgsk_[A-Za-z0-9]{40,90}"""),
            remediation = "Revoke the key in the Groq console.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-HUGGINGFACE", "Hardcoded HuggingFace token", Severity.HIGH,
            gates = listOf("hf_"),
            regex = Regex("""\bhf_[A-Za-z0-9]{30,70}"""),
            remediation = "Revoke the token; a write token can overwrite published models.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-REPLICATE", "Hardcoded Replicate token", Severity.HIGH,
            gates = listOf("r8_"),
            regex = Regex("""\br8_[A-Za-z0-9]{30,70}"""),
            remediation = "Revoke the token in Replicate.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-OPENROUTER", "Hardcoded OpenRouter key", Severity.HIGH,
            gates = listOf("sk-or-v1-"),
            regex = Regex("""sk-or-v1-[a-f0-9]{40,90}"""),
            remediation = "Revoke the key; one OpenRouter key bills against every upstream provider.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-XAI", "Hardcoded xAI API key", Severity.HIGH,
            gates = listOf("xai-"),
            regex = Regex("""\bxai-[A-Za-z0-9]{40,90}"""),
            remediation = "Revoke the key in the xAI console.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-FIREWORKS", "Hardcoded Fireworks AI key", Severity.HIGH,
            gates = listOf("fw_"),
            regex = Regex("""\bfw_[A-Za-z0-9]{20,70}"""),
            remediation = "Revoke the key in Fireworks.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),

        // ---- messaging / webhooks ------------------------------------------
        SecretRule(
            "SEC-WEBHOOK-SLACK", "Slack incoming webhook URL", Severity.HIGH,
            gates = listOf("hooks.slack.com"),
            regex = Regex("""https://hooks\.slack\.com/services/T[A-Z0-9]{5,}/B[A-Z0-9]{5,}/[A-Za-z0-9]{20,}"""),
            remediation = "Delete the webhook in Slack; anything with the URL can post to the channel.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-WEBHOOK-DISCORD", "Discord webhook URL", Severity.HIGH,
            gates = listOf("discord.com/api/webhooks", "discordapp.com/api/webhooks"),
            regex = Regex("""https://(?:discord|discordapp)\.com/api/webhooks/\d{15,25}/[A-Za-z0-9_\-]{50,120}"""),
            remediation = "Delete the webhook in Discord.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-POSTMARK", "Hardcoded Postmark server token", Severity.HIGH,
            gates = listOf("pmk_"),
            regex = Regex("""\bpmk_[A-Za-z0-9]{20,70}"""),
            remediation = "Revoke the server token; it can send mail as your domain.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-MAILGUN", "Hardcoded Mailgun private key", Severity.HIGH,
            gates = listOf("mailgun"),
            regex = Regex("""\bkey-[a-f0-9]{32}\b"""),
            remediation = "Rotate the Mailgun private key.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),

        // ---- cloud / infrastructure ----------------------------------------
        SecretRule(
            "SEC-GCP-SERVICE-ACCOUNT", "Google service-account credential JSON", Severity.CRITICAL,
            gates = listOf("service_account"),
            regex = Regex(""""type"\s*:\s*"service_account""""),
            secret = false,
            note = "Marker only: the embedded private_key is reported separately as SEC-KEY-PRIVATE.",
            remediation = "Remove the service-account file from the app; use a scoped backend.",
            masvs = listOf("MASVS-CODE-4"),
        ),
        SecretRule(
            "SEC-AZURE-ACCOUNT-KEY", "Azure Storage account key", Severity.CRITICAL,
            gates = listOf("accountkey="),
            regex = Regex("""AccountKey=[A-Za-z0-9+/]{60,}={0,2}"""),
            remediation = "Rotate the storage key; it grants full access to the account.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-DIGITALOCEAN", "Hardcoded DigitalOcean token", Severity.HIGH,
            gates = listOf("dop_v1_"),
            regex = Regex("""dop_v1_[a-f0-9]{64}"""),
            remediation = "Revoke the token in DigitalOcean.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-GITHUB-PAT", "Hardcoded GitHub fine-grained token", Severity.HIGH,
            gates = listOf("github_pat_"),
            regex = Regex("""github_pat_[A-Za-z0-9_]{60,120}"""),
            remediation = "Revoke the token on GitHub; check its repository scope.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-GITLAB", "Hardcoded GitLab token", Severity.HIGH,
            gates = listOf("glpat-"),
            regex = Regex("""glpat-[A-Za-z0-9_\-]{20,70}"""),
            remediation = "Revoke the token in GitLab.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-NPM", "Hardcoded npm token", Severity.HIGH,
            gates = listOf("npm_"),
            regex = Regex("""\bnpm_[A-Za-z0-9]{36}\b"""),
            remediation = "Revoke the token on npm; a publish token can ship a malicious release.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-POSTMAN", "Hardcoded Postman API key", Severity.MEDIUM,
            gates = listOf("pmak-"),
            regex = Regex("""PMAK-[a-f0-9]{24}-[a-f0-9]{34}"""),
            remediation = "Revoke the key in Postman.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-DOCKER", "Hardcoded Docker registry token", Severity.HIGH,
            gates = listOf("dckr_pat_"),
            regex = Regex("""dckr_pat_[A-Za-z0-9_\-]{20,70}"""),
            remediation = "Revoke the token in Docker Hub.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),

        // ---- SaaS ----------------------------------------------------------
        SecretRule(
            "SEC-KEY-AIRTABLE", "Hardcoded Airtable personal access token", Severity.HIGH,
            gates = listOf("airtable"),
            regex = Regex("""\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b"""),
            remediation = "Revoke the token in Airtable.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-NOTION", "Hardcoded Notion integration token", Severity.HIGH,
            gates = listOf("secret_"),
            regex = Regex("""\bsecret_[A-Za-z0-9]{43}\b"""),
            remediation = "Revoke the integration in Notion; it can read shared workspaces.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),
        SecretRule(
            "SEC-KEY-LINEAR", "Hardcoded Linear API key", Severity.MEDIUM,
            gates = listOf("lin_api_"),
            regex = Regex("""lin_api_[A-Za-z0-9]{30,50}"""),
            remediation = "Revoke the key in Linear.",
            masvs = listOf("MASVS-NETWORK-2"),
        ),

        // ---- transport -----------------------------------------------------
        SecretRule(
            "SEC-BEARER-JWT", "Hardcoded bearer JWT", Severity.HIGH,
            gates = listOf("bearer "),
            regex = Regex("""Bearer\s+eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"""),
            remediation = "Remove the static token; issue short-lived tokens from the backend.",
            masvs = listOf("MASVS-AUTH-1"),
        ),

        // ---- weak crypto ---------------------------------------------------
        SecretRule(
            "SEC-CRYPTO-ECB", "AES in ECB mode", Severity.MEDIUM,
            gates = listOf("aes/ecb"),
            regex = Regex("""(?:AES|aes)/ECB/[A-Za-z0-9]+"""),
            secret = false,
            note = "ECB leaks plaintext structure; it is a cipher-mode choice, not a leak by itself.",
            remediation = "Use AES/GCM with a random IV.",
            masvs = listOf("MASVS-CRYPTO-1"),
        ),
    )
}
