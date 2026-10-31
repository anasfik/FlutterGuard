package com.flutterguard.app.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The hand-rolled back stack: every screen is a route, hardware Back pops one
 * route, and the root is never popped. Payload encoding is part of the same
 * contract because it is what survives a rotation.
 */
class NavStackTest {

    private val home = Destination.Home
    private val details = Destination.Details("com.example.app")
    private val section = Destination.Section("com.example.app", SeeAllTarget.HOSTS)

    @Test
    fun theRootIsHomeAndCannotBePopped() {
        val stack = NavStack.root()
        assertEquals(listOf<Destination>(home), stack)
        assertEquals(home, NavStack.current(stack))
        assertFalse(NavStack.canPop(stack))

        // Back at the root is a no-op, not an empty or crashed stack.
        assertEquals(stack, NavStack.pop(stack))
        assertEquals(home, NavStack.current(NavStack.pop(stack)))
        assertFalse(NavStack.canPop(NavStack.pop(stack)))
    }

    @Test
    fun aSeeAllRouteRemembersTheNamespaceItWasOpenedFrom() {
        val fileSection = Destination.Section(
            "com.example.app",
            SeeAllTarget.HOSTS,
            "",
            fileScan = true,
        )
        val installed = Destination.Section("com.example.app", SeeAllTarget.HOSTS)
        // Identity: a saved state is not shared between the two namespaces.
        assertNotEquals(NavStack.stateKey(installed), NavStack.stateKey(fileSection))
        // Round trip: the flag survives a restart, which is the only reason it exists.
        assertEquals(fileSection, NavStack.decode(NavStack.encode(fileSection)))
        // A save written before sections carried the flag has four fields: the
        // filter was the last one, so a stale filter is dropped, not misread.
        val legacy = "section\u001Fcom.example.app\u001F${SeeAllTarget.HOSTS.name}\u001FAI providers"
        assertEquals(installed, NavStack.decode(legacy))
    }

    @Test
    fun backOrderIsSectionThenDetailsThenHome() {
        val stack = NavStack.push(NavStack.push(NavStack.root(), details), section)
        assertEquals(listOf(home, details, section), stack)
        assertEquals(section, NavStack.current(stack))
        assertTrue(NavStack.canPop(stack))

        val afterFirstBack = NavStack.pop(stack)
        assertEquals(listOf(home, details), afterFirstBack)
        assertTrue(NavStack.canPop(afterFirstBack))

        val afterSecondBack = NavStack.pop(afterFirstBack)
        assertEquals(listOf(home), afterSecondBack)
        assertFalse("third Back belongs to the system, not the stack", NavStack.canPop(afterSecondBack))
    }

    @Test
    fun pushingTheSameDestinationTwiceDoesNotDuplicateIt() {
        val stack = NavStack.push(NavStack.root(), details)
        assertEquals(stack, NavStack.push(stack, details))
        assertEquals(stack, NavStack.push(stack, Destination.Details("com.example.app")))

        // A different payload is a different route: no dedupe across apps.
        val other = NavStack.push(stack, Destination.Details("com.other.app"))
        assertEquals(listOf(home, details, Destination.Details("com.other.app")), other)
        assertEquals(Destination.Details("com.other.app"), NavStack.current(other))
    }

    @Test
    fun everyDestinationRoundTripsThroughItsSavedForm() {
        val stack = listOf(home, details, Destination.Section("com.other.app", SeeAllTarget.DEPENDENCIES, "dio"))
        assertEquals(stack, NavStack.restore(NavStack.save(stack)))
    }

    @Test
    fun aFileScanRouteRemembersItsOwnReportNamespace() {
        // A picked APK that declares an installed package reads its own `.file`
        // report; losing the flag on restore would show the installed app's verdict.
        val picked = Destination.Details("com.whatsapp", fileScan = true)
        val stack = NavStack.push(NavStack.root(), picked)
        assertEquals(picked, NavStack.restore(NavStack.save(stack)).last())
        assertEquals(picked, NavStack.decode(NavStack.encode(picked)))
        assertNotEquals(NavStack.stateKey(picked), NavStack.stateKey(Destination.Details("com.whatsapp")))
        // A save written before the flag existed still resolves to the installed app.
        assertEquals(
            Destination.Details("com.whatsapp", "Findings", fileScan = false),
            NavStack.decode("details\u001Fcom.whatsapp\u001FFindings"),
        )
    }

    @Test
    fun theOpenTabIsPartOfTheDetailsRouteSoASeeAllReturnsToIt() {
        val onExplore = Destination.Details("com.example.app", section = "Explore")
        val stack = NavStack.push(NavStack.push(NavStack.root(), onExplore), section)
        assertEquals(onExplore, NavStack.pop(stack).last())
        assertEquals(onExplore, NavStack.restore(NavStack.save(stack))[1])

        // A tab switch updates the visible route instead of stacking a new one.
        val switched = NavStack.replaceTop(NavStack.root(), Destination.Details("com.example.app", "Findings"))
        assertEquals(1, switched.size)
        assertEquals("Findings", (switched.last() as Destination.Details).section)
        assertEquals(Destination.Home, NavStack.current(NavStack.replaceTop(emptyList(), Destination.Home)))
    }

    @Test
    fun theQueueIsItsOwnRouteAndDetailsOpenedFromItReturnsToTheQueue() {
        val queue = Destination.Queue
        val stack = NavStack.push(NavStack.push(NavStack.root(), queue), details)
        assertEquals(listOf(home, queue, details), stack)
        // Back from a queue row lands on the queue, not on Home.
        assertEquals(queue, NavStack.pop(stack).last())
        // Re-entering the queue from Home does not stack a second one.
        val onQueue = NavStack.push(NavStack.root(), queue)
        assertEquals(onQueue, NavStack.push(onQueue, queue))
        // The route survives rotation like every other destination.
        assertEquals(stack, NavStack.restore(NavStack.save(stack)))
        assertEquals(queue, NavStack.decode(NavStack.encode(queue)))
    }

    @Test
    fun aSavedQueryContainingTheFieldSeparatorSurvives() {
        val tricky = Destination.Section("com.example.app", SeeAllTarget.ARTIFACTS, "a|b\u001Fc\nz")
        val stack = listOf(home, tricky)
        assertEquals(stack, NavStack.restore(NavStack.save(stack)))
    }

    @Test
    fun aCorruptSaveFallsBackToTheRootInsteadOfCrashing() {
        assertEquals(NavStack.root(), NavStack.restore(emptyList()))
        assertEquals(NavStack.root(), NavStack.restore(listOf("garbage", "details\u001Fcom.a")))
        // A stack that does not start at Home is not a stack we produced.
        assertEquals(NavStack.root(), NavStack.restore(listOf("details\u001Fcom.a")))
        // An unknown section target cannot be decoded back into a route.
        assertEquals(NavStack.root(), NavStack.restore(listOf("section\u001Fcom.a\u001FNOPE")))
        assertNull(NavStack.decode("nonsense"))
    }
}
