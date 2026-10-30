package com.flutterguard.app.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Defaults must reproduce the shipped 0.3.x behaviour with settings untouched,
 * and consent is the single gate for the installed-app inventory path.
 */
class SettingsPolicyTest {

    @Test
    fun defaultsMatchTodaysBehaviour() {
        val d = SettingsState()
        assertTrue("result notifications were on", d.notifications)
        assertTrue("reveal was available", d.revealSecrets)
        assertTrue("the per-export sensitive opt-in existed", d.sensitiveExport)
        assertTrue("history was always written", d.keepHistory)
        assertTrue("scan-all was available", d.scanAll)
        assertFalse("there was no update prompt", d.rescanPrompt)
    }

    @Test
    fun sensitiveExportStillDefaultsToRedacted() {
        // The setting only permits the dialog's opt-in; an export is redacted
        // unless the user asks for raw values in that dialog.
        val d = SettingsState()
        assertFalse("no request means redacted", d.exportSensitive(requested = false))
    }

    @Test
    fun sensitiveExportNeedsBothTheSettingAndThePerExportOptIn() {
        val off = SettingsState(sensitiveExport = false)
        assertFalse(off.exportSensitive(requested = true))
        assertFalse(off.exportSensitive(requested = false))

        val on = SettingsState(sensitiveExport = true)
        assertFalse(on.exportSensitive(requested = false))
        assertTrue(on.exportSensitive(requested = true))
    }

    @Test
    fun revealFollowsItsOwnToggle() {
        assertTrue(SettingsState(revealSecrets = true).canRevealSecrets)
        assertFalse(SettingsState(revealSecrets = false).canRevealSecrets)
    }

    @Test
    fun disclosureIsRequiredUntilTheCurrentPolicyIsAccepted() {
        assertTrue(ConsentPolicy.needsDisclosure(0))
        assertTrue(ConsentPolicy.needsDisclosure(ConsentPolicy.POLICY_VERSION - 1))
        assertFalse(ConsentPolicy.needsDisclosure(ConsentPolicy.POLICY_VERSION))
    }

    @Test
    fun inventoryNeedsBothTheCurrentPolicyAndExplicitConsent() {
        assertFalse("fresh install", ConsentPolicy.inventoryAllowed(0, false))
        assertFalse("accepted an older policy", ConsentPolicy.inventoryAllowed(0, true))
        assertFalse("declined the current policy", ConsentPolicy.inventoryAllowed(ConsentPolicy.POLICY_VERSION, false))
        assertTrue("agreed to the current policy", ConsentPolicy.inventoryAllowed(ConsentPolicy.POLICY_VERSION, true))
    }

    @Test
    fun decliningIsAStoredDecisionNotAPromptLoop() {
        // Decline writes the current version with consent false: the disclosure
        // is not shown again until the policy version advances.
        val declined = SettingsState(consentVersion = ConsentPolicy.POLICY_VERSION, inventoryConsent = false)
        assertFalse(ConsentPolicy.needsDisclosure(declined.consentVersion))
        assertFalse(declined.inventoryAllowed())
        assertEquals(false, declined.copy(consentVersion = 0).inventoryAllowed())
    }

    @Test
    fun withdrawingReturnsToTheDisclosure() {
        val agreed = SettingsState(consentVersion = ConsentPolicy.POLICY_VERSION, inventoryConsent = true)
        assertTrue(agreed.inventoryAllowed())
        val withdrawn = agreed.copy(consentVersion = 0, inventoryConsent = false)
        assertTrue(ConsentPolicy.needsDisclosure(withdrawn.consentVersion))
        assertFalse(withdrawn.inventoryAllowed())
    }
}
