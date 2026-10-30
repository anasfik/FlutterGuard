package com.flutterguard.app.settings

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The privacy disclosure version. Bump only when the disclosure or policy text
 * changes materially: a stored consent older than this re-prompts on launch and
 * blocks installed-app inventory until the user agrees again.
 */
object ConsentPolicy {
    const val POLICY_VERSION = 1

    /** True when this install has never accepted the current policy text. */
    fun needsDisclosure(consentVersion: Int): Boolean = consentVersion < POLICY_VERSION

    /**
     * The installed-app inventory path (QUERY_ALL_PACKAGES) is allowed only after
     * an explicit agree for the current policy. Declining or withdrawing sets
     * [inventoryConsent] false and leaves file-pick scans available.
     */
    fun inventoryAllowed(consentVersion: Int, inventoryConsent: Boolean): Boolean =
        consentVersion >= POLICY_VERSION && inventoryConsent
}

/**
 * Every preference that changes behaviour. Defaults are the shipped 0.3.x
 * behaviour: notifications on, reveal allowed, exports redacted, history kept,
 * scan-all available, and no update prompt (there was none before).
 *
 * Consent is the one deliberate exception: a fresh install starts at version 0,
 * so the disclosure is shown before any installed-app enumeration.
 */
data class SettingsState(
    val notifications: Boolean = true,
    val revealSecrets: Boolean = true,
    /**
     * On by default so an untouched install keeps the per-export opt-in that
     * shipped before this setting existed; turning it off is the hard redaction
     * ceiling. The export dialog still defaults to redacted.
     */
    val sensitiveExport: Boolean = true,
    val keepHistory: Boolean = true,
    val scanAll: Boolean = true,
    val rescanPrompt: Boolean = false,
    val consentVersion: Int = 0,
    val inventoryConsent: Boolean = false,
) {
    /** Reveal action availability, read by the findings UI. */
    val canRevealSecrets: Boolean get() = revealSecrets

    /** An export can carry raw values only when both the toggle and the user opt-in allow it. */
    fun exportSensitive(requested: Boolean): Boolean = requested && sensitiveExport

    /** The single gate for the installed-app inventory path. */
    fun inventoryAllowed(): Boolean = ConsentPolicy.inventoryAllowed(consentVersion, inventoryConsent)
}

/**
 * SharedPreferences-backed settings behind one observable snapshot. The service
 * reads [snapshot] directly (it may start without the activity); the UI collects
 * [state] so a toggle takes effect on the next scan rather than after a restart.
 *
 * ponytail: one key per field, all rewritten on every change. A preference store
 * with migrations is not warranted until a field is renamed.
 */
object Settings {

    const val PREFS = "flutterguard_settings"

    private const val K_NOTIFICATIONS = "notifications"
    private const val K_REVEAL = "reveal_secrets"
    private const val K_SENSITIVE_EXPORT = "sensitive_export"
    private const val K_KEEP_HISTORY = "keep_history"
    private const val K_SCAN_ALL = "scan_all"
    private const val K_RESCAN_PROMPT = "rescan_prompt"
    private const val K_CONSENT_VERSION = "consent_version"
    private const val K_INVENTORY_CONSENT = "inventory_consent"

    private val _state = MutableStateFlow(SettingsState())
    val state: StateFlow<SettingsState> = _state.asStateFlow()

    /** Reads storage without touching the observable state (safe from a Service). */
    fun snapshot(context: Context): SettingsState {
        val p = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val d = SettingsState()
        return SettingsState(
            notifications = p.getBoolean(K_NOTIFICATIONS, d.notifications),
            revealSecrets = p.getBoolean(K_REVEAL, d.revealSecrets),
            sensitiveExport = p.getBoolean(K_SENSITIVE_EXPORT, d.sensitiveExport),
            keepHistory = p.getBoolean(K_KEEP_HISTORY, d.keepHistory),
            scanAll = p.getBoolean(K_SCAN_ALL, d.scanAll),
            rescanPrompt = p.getBoolean(K_RESCAN_PROMPT, d.rescanPrompt),
            consentVersion = p.getInt(K_CONSENT_VERSION, d.consentVersion),
            inventoryConsent = p.getBoolean(K_INVENTORY_CONSENT, d.inventoryConsent),
        )
    }

    /** Hydrates [state] from storage; called once when the activity starts. */
    fun load(context: Context): SettingsState = snapshot(context).also { _state.value = it }

    /** Applies [transform] to the stored snapshot, persists it and publishes it. */
    fun update(context: Context, transform: (SettingsState) -> SettingsState): SettingsState {
        val next = transform(snapshot(context))
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(K_NOTIFICATIONS, next.notifications)
            .putBoolean(K_REVEAL, next.revealSecrets)
            .putBoolean(K_SENSITIVE_EXPORT, next.sensitiveExport)
            .putBoolean(K_KEEP_HISTORY, next.keepHistory)
            .putBoolean(K_SCAN_ALL, next.scanAll)
            .putBoolean(K_RESCAN_PROMPT, next.rescanPrompt)
            .putInt(K_CONSENT_VERSION, next.consentVersion)
            .putBoolean(K_INVENTORY_CONSENT, next.inventoryConsent)
            .apply()
        _state.value = next
        return next
    }
}
