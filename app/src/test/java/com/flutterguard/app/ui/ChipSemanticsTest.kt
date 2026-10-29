package com.flutterguard.app.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Label/state/role resolution only. It does NOT prove the composable emits one
 * node: no compose-ui-test artifact is available offline, so the semantics node
 * count for `WorkbenchChip` stays in the device-pending list (one
 * `uiautomator dump` showing no empty CheckBox per segment is the real check).
 */
class ChipSemanticsTest {

    @Test
    fun labelIsResolvedFromTheSegmentAndNeverEmpty() {
        assertEquals("Explore", Segments.of("Explore", selected = false).label)
        assertEquals("Findings", Segments.of("  Findings  ", selected = true).label)
        assertEquals(Segments.FALLBACK_LABEL, Segments.of("   ", selected = false).label)
    }

    @Test
    fun selectionResolvesToTabStateNotACheckbox() {
        val selected = Segments.of("Explore", selected = true)
        assertTrue(selected.selected)
        assertEquals("Selected", selected.stateDescription)
        assertEquals(SegmentRole.TAB, selected.role)

        val unselected = Segments.of("Overview", selected = false)
        assertEquals("Not selected", unselected.stateDescription)
        assertEquals(SegmentRole.TAB, unselected.role)
        assertFalse(unselected.role == SegmentRole.CHECKBOX)
    }

    /**
     * Compact pill, full-size target. These constants are what the composable
     * uses, so a chip that grows into a 48 dp pill or shrinks its target fails
     * here before it reaches the device.
     */
    @Test
    fun thePillIsCompactButItsTouchTargetIsStill48() {
        assertEquals(48, ChipMetrics.TOUCH_DP)
        assertTrue("pill ${ChipMetrics.PILL_DP} dp must stay in 32..36", ChipMetrics.PILL_DP in 32..36)
        assertTrue("the pill must be shorter than the target", ChipMetrics.PILL_DP < ChipMetrics.TOUCH_DP)
        assertTrue("chips are tighter than the old 16 dp sides", ChipMetrics.PAD_H_DP < 16)
        assertTrue("vertical padding must fit inside the pill", ChipMetrics.PAD_V_DP * 2 < ChipMetrics.PILL_DP)
    }
}
