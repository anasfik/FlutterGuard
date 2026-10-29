package com.flutterguard.app.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The stepper only maps stages the scanner really reports; unknown stages stay at the start. */
class ScanStepperTest {

    @Test
    fun everyRealScannerStageMapsToItsStep() {
        val expected = mapOf(
            "Starting…" to 0,
            "Reading package info" to 1,
            "Opening APK artifacts" to 1,
            "Decoding AndroidManifest" to 2,
            "Scanning resource strings" to 2,
            "Decoding res/xml" to 2,
            "Extracting DEX strings" to 3,
            "Analyzing native libraries" to 3,
            "Scanning Dart kernel" to 4,
            "Kernel strings scanned (1200)" to 4,
            "Scanning assets" to 4,
            "Evaluating network security" to 5,
            "Verifying signing" to 5,
            "Composing report" to 6,
            "Done" to 6,
        )
        expected.forEach { (stage, index) ->
            assertEquals(stage, index, ScanStepper.indexOf(stage))
        }
    }

    @Test
    fun unknownStageNeverClaimsProgressItDoesNotHave() {
        assertEquals(0, ScanStepper.indexOf("Something new"))
        val stepper = ScanStepper.of("Something new", 12)
        assertEquals(0, stepper.activeIndex)
        assertEquals(12, stepper.pct)
        assertEquals(StepPhase.ACTIVE, stepper.steps[0].phase)
        assertEquals(StepPhase.PENDING, stepper.steps[1].phase)
    }

    @Test
    fun stepsBeforeTheActiveStageAreDone() {
        val stepper = ScanStepper.of("Analyzing native libraries", 55)
        assertEquals(7, stepper.steps.size)
        assertEquals(StepPhase.DONE, stepper.steps[0].phase)
        assertEquals(StepPhase.DONE, stepper.steps[2].phase)
        assertEquals(StepPhase.ACTIVE, stepper.steps[3].phase)
        assertEquals("Native", stepper.steps[3].label)
        assertEquals(StepPhase.PENDING, stepper.steps[4].phase)
        assertFalse(stepper.terminal)
    }

    @Test
    fun doneCompletesEveryStep() {
        val stepper = ScanStepper.of("Done", 100)
        assertTrue(stepper.terminal)
        assertTrue(stepper.steps.all { it.phase == StepPhase.DONE })
    }

    @Test
    fun percentageIsClampedAndNeverFabricated() {
        assertEquals(0, ScanStepper.of("Reading package info", -5).pct)
        assertEquals(100, ScanStepper.of("Done", 140).pct)
    }
}
