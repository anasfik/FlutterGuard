package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.Provenance
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * One positive sample per provider rule, plus the negative that matters most:
 * ordinary code and URLs must not be reported as provider credentials. The
 * samples are synthesised, never real keys.
 */
class ProviderSecretsTest {

    private fun ids(text: String): Set<String> {
        val scanner = SecretScanner()
        scanner.feed(text, Provenance("test", 0), Layer.DEX)
        return scanner.toFindingList().map { it.id }.toSet()
    }

    private val samples: Map<String, String> = mapOf(
        "SEC-KEY-ANTHROPIC" to "k = \"sk-ant-api03-abcdefghijklmnopqrstuvwxyz\"",
        "SEC-KEY-OPENAI-PROJECT" to "k = \"sk-proj-abc123def456ghi789jkl012mno\"",
        "SEC-KEY-GROQ" to "k = \"gsk_" + "a".repeat(44) + "\"",
        "SEC-KEY-HUGGINGFACE" to "k = \"hf_" + "b".repeat(34) + "\"",
        "SEC-KEY-REPLICATE" to "k = \"r8_" + "c".repeat(34) + "\"",
        "SEC-KEY-OPENROUTER" to "k = \"sk-or-v1-" + "d".repeat(48) + "\"",
        "SEC-KEY-XAI" to "k = \"xai-" + "e".repeat(48) + "\"",
        "SEC-KEY-FIREWORKS" to "k = \"fw_" + "f".repeat(24) + "\"",
        "SEC-WEBHOOK-SLACK" to "https://hooks.slack.com/services/T0000000/B0000000/abcdefghijklmnopqrstuvwxyz",
        "SEC-WEBHOOK-DISCORD" to "https://discord.com/api/webhooks/123456789012345678/" + "a".repeat(60),
        "SEC-KEY-POSTMARK" to "k = \"pmk_" + "g".repeat(24) + "\"",
        // Assembled at runtime: a literal key-shaped string trips push protection.
        "SEC-KEY-MAILGUN" to "mailgun key-" + "0123456789abcdef".repeat(2),
        "SEC-GCP-SERVICE-ACCOUNT" to "{\"type\": \"service_account\"}",
        "SEC-AZURE-ACCOUNT-KEY" to "AccountKey=" + "A".repeat(70),
        "SEC-KEY-DIGITALOCEAN" to "token dop_v1_" + "0".repeat(64),
        "SEC-KEY-GITHUB-PAT" to "github_pat_" + "h".repeat(64),
        "SEC-KEY-GITLAB" to "glpat-" + "i".repeat(24),
        "SEC-KEY-NPM" to "//registry.npmjs.org/:_authToken=npm_" + "j".repeat(36),
        "SEC-KEY-POSTMAN" to "PMAK-0123456789abcdef01234567-" + "a".repeat(34),
        "SEC-KEY-DOCKER" to "dckr_pat_" + "k".repeat(24),
        "SEC-KEY-AIRTABLE" to "airtable pat" + "L".repeat(14) + "." + "a".repeat(64),
        "SEC-KEY-NOTION" to "secret_" + "l".repeat(43),
        "SEC-KEY-LINEAR" to "lin_api_" + "m".repeat(32),
        "SEC-BEARER-JWT" to "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij",
        "SEC-CRYPTO-ECB" to "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")",
    )

    @Test
    fun everyProviderRuleFiresOnItsOwnSample() {
        for ((id, sample) in samples) {
            assertTrue("$id did not fire on: $sample", id in ids(sample))
        }
    }

    @Test
    fun ordinaryCodeAndUrlsAreNotCredentials() {
        val text = """
            https://api.example.com/v1/users?page=2
            SharedPreferences settings = getSharedPreferences("prefs", 0);
            Token refresh scheduled at 30 seconds.
        """.trimIndent()
        val found = ids(text)
        val leaked = found.filter { it in samples.keys }
        assertFalse("plain code matched provider rules: $leaked", leaked.isNotEmpty())
    }

    @Test
    fun providerRulesAreDeduplicatedPerValue() {
        val sample = "aws_secret = \"" + "sk-ant-api03-abcdefghijklmnopqrstuvwxyz" + "\""
        val hits = SecretScanner().apply {
            feed(sample, Provenance("test", 0), Layer.DEX)
            feed(sample, Provenance("test", 0), Layer.DEX)
        }.toFindingList().filter { it.id == "SEC-KEY-ANTHROPIC" }
        assertTrue("the same key reported twice", hits.size == 1)
    }
}
