package com.flutterguard.app.scan

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Installed-app inventory state. Kept outside the list composable so Back,
 * rotation and navigation never re-enumerate packages, while an explicit
 * refresh can still show progress and failures.
 */
data class InventoryState(
    val apps: List<InstalledApp> = emptyList(),
    val loading: Boolean = false,
    /** Last discovery error; the previous [apps] are kept so the list is not silently emptied. */
    val error: String? = null,
    val loadedAtMs: Long? = null,
) {
    val hasData: Boolean get() = loadedAtMs != null

    /** Null when a discovery is already in flight: refresh is explicit and never duplicated. */
    fun begin(): InventoryState? = if (loading) null else copy(loading = true, error = null)

    fun loaded(apps: List<InstalledApp>, now: Long): InventoryState =
        InventoryState(apps = apps, loading = false, error = null, loadedAtMs = now)

    fun failed(message: String): InventoryState = copy(loading = false, error = message)
}

object InventoryStore {

    private val _state = MutableStateFlow(InventoryState())
    val state: StateFlow<InventoryState> = _state.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val inFlight = AtomicBoolean(false)

    /**
     * Starts a discovery unless one is running. [force] distinguishes the
     * explicit refresh action from the initial load of an already cached list.
     */
    fun refresh(context: Context, force: Boolean = false): Boolean {
        val current = _state.value
        if (current.hasData && !force) return false
        val loading = current.begin() ?: return false
        if (!inFlight.compareAndSet(false, true)) return false
        _state.value = loading

        val appContext = context.applicationContext
        scope.launch {
            try {
                runCatching { Discovery.loadApps(appContext) }
                    .onSuccess { _state.value = _state.value.loaded(it, System.currentTimeMillis()) }
                    .onFailure { t ->
                        _state.value = _state.value.failed(t.message ?: t::class.java.simpleName)
                    }
            } finally {
                inFlight.set(false)
            }
        }
        return true
    }

    /** Test hook. */
    fun reset() {
        inFlight.set(false)
        _state.value = InventoryState()
    }
}
