package com.flutterguard.app.ui

/**
 * Every screen the user can be on. A destination is pushed and popped as a
 * whole route; nothing renders as an in-place subview of another destination.
 * Payloads are exactly what the route needs to rebuild itself from disk, so a
 * route survives leaving and returning (and a rotation, via [NavStack.save]).
 */
sealed interface Destination {

    data object Home : Destination

    /**
     * One app's audit workspace. [section] is the visible tab, held by the
     * route (not by the composable) so opening a See-all list — or rotating —
     * returns to the tab the user was reading.
     */
    data class Details(
        val packageName: String,
        val section: String = DetailsSections.first(),
    ) : Destination

    /** A See-all list. [filter] is the section's own filter at the moment it was opened. */
    data class Section(
        val packageName: String,
        val target: SeeAllTarget,
        val filter: String = "",
    ) : Destination

    /**
     * The scan-all queue. It carries no payload: the queue itself is
     * `ScanQueueRunner.state`, so the route only says "show it". A queue row
     * pushes [Details] on top of this route, so Back returns here.
     */
    data object Queue : Destination
}

/**
 * The one navigation source of truth: a plain list of destinations, the last
 * one visible. Hardware Back, the app-bar arrows and predictive back pop here.
 *
 * ponytail: the stack is saved for rotation but not for process death beyond
 * what `rememberSaveable` restores; a killed process returns to Home rather
 * than to a half-restored route with a stale payload.
 */
object NavStack {

    /** Unit separator: legal in a package name and in a typed query, so the last field is length-free. */
    private const val SEP = '\u001F'

    fun root(): List<Destination> = listOf(Destination.Home)

    /** No duplicate rows: pushing the destination already on top is a no-op. */
    fun push(stack: List<Destination>, next: Destination): List<Destination> =
        if (stack.lastOrNull() == next) stack else stack + next

    /** Pops one route. The root is never popped — at Home, Back belongs to the system. */
    fun pop(stack: List<Destination>): List<Destination> =
        if (stack.size <= 1) stack else stack.dropLast(1)

    /** Updates the visible route in place (a tab switch is not a new destination). */
    fun replaceTop(stack: List<Destination>, next: Destination): List<Destination> =
        if (stack.isEmpty()) listOf(next) else stack.dropLast(1) + next

    fun current(stack: List<Destination>): Destination = stack.lastOrNull() ?: Destination.Home

    fun canPop(stack: List<Destination>): Boolean = stack.size > 1

    /**
     * Identity used to keep a route's saved state alive while another route
     * renders. A Details tab is a field of the route, not a new screen, so
     * switching tabs keeps one saved state; a different package, target or
     * screen is a different identity.
     */
    fun stateKey(destination: Destination): String = when (destination) {
        Destination.Home -> "home"
        Destination.Queue -> "queue"
        is Destination.Details -> "details\u001F${destination.packageName}"
        is Destination.Section -> "section\u001F${destination.packageName}\u001F${destination.target.name}"
    }

    fun save(stack: List<Destination>): List<String> = stack.map(::encode)

    /** A save that does not start at Home is not one we produced: fall back to the root. */
    fun restore(saved: List<String>): List<Destination> {
        val stack = saved.mapNotNull(::decode)
        return if (stack.firstOrNull() == Destination.Home) stack else root()
    }

    fun encode(destination: Destination): String = when (destination) {
        Destination.Home -> "home"
        Destination.Queue -> "queue"
        is Destination.Details -> "details$SEP${destination.packageName}$SEP${destination.section}"
        is Destination.Section ->
            "section$SEP${destination.packageName}$SEP${destination.target.name}$SEP${destination.filter}"
    }

    /** Null for anything unrecognised, so a corrupt save degrades to Home instead of crashing. */
    fun decode(raw: String): Destination? {
        // limit = 4 keeps the filter intact even if it contains the separator.
        val parts = raw.split(SEP, limit = 4)
        return when (parts[0]) {
            "home" -> Destination.Home
            "queue" -> Destination.Queue
            "details" -> parts.getOrNull(1)?.takeIf { it.isNotBlank() }?.let { packageName ->
                Destination.Details(packageName, parts.getOrNull(2).orEmpty().ifBlank { DetailsSections.first() })
            }
            "section" -> {
                val packageName = parts.getOrNull(1)?.takeIf { it.isNotBlank() } ?: return null
                val target = parts.getOrNull(2)?.let { name -> SeeAllTarget.entries.firstOrNull { it.name == name } }
                    ?: return null
                Destination.Section(packageName, target, parts.getOrNull(3).orEmpty())
            }
            else -> null
        }
    }
}
