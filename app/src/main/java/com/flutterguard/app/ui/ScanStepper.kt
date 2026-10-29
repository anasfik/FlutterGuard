package com.flutterguard.app.ui

import android.animation.ValueAnimator
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

/** One step of the staged scan progress. */
enum class StepPhase { DONE, ACTIVE, PENDING }

data class StepperStep(val label: String, val phase: StepPhase)

data class StepperState(
    val steps: List<StepperStep>,
    val activeIndex: Int,
    val pct: Int,
    val terminal: Boolean,
) {
    val activeLabel: String get() = steps.getOrNull(activeIndex)?.label ?: steps.first().label
}

/**
 * Maps the scanner's real stage strings to the seven named steps. Unknown or
 * empty stages stay at "Queued": the stepper never claims progress that the
 * scan state has not reported.
 */
object ScanStepper {

    val LABELS = listOf("Queued", "Discover", "Parse", "Native", "Strings", "Rules", "Report")

    fun indexOf(stage: String): Int {
        val s = stage.lowercase()
        return when {
            s.isBlank() || s.contains("starting") || s.contains("queued") -> 0
            s.contains("package info") || s.contains("discover") || s.contains("opening apk") -> 1
            s.contains("manifest") || s.contains("res/xml") || s.contains("resource string") -> 2
            s.contains("dex") || s.contains("native") -> 3
            s.contains("kernel") || s.contains("dart") || s.contains("asset") -> 4
            s.contains("network") || s.contains("signing") || s.contains("rules") -> 5
            s.contains("composing") || s.contains("report") || s.contains("done") -> 6
            else -> 0
        }
    }

    fun of(stage: String, pct: Int): StepperState {
        val clamped = pct.coerceIn(0, 100)
        val index = indexOf(stage)
        val complete = stage.equals("Done", ignoreCase = true) || clamped >= 100
        val steps = LABELS.mapIndexed { i, label ->
            StepperStep(
                label,
                when {
                    complete -> StepPhase.DONE
                    i < index -> StepPhase.DONE
                    i == index -> StepPhase.ACTIVE
                    else -> StepPhase.PENDING
                },
            )
        }
        return StepperState(steps, if (complete) LABELS.lastIndex else index, clamped, complete)
    }
}

/** One state word per intent; the stepper never invents a fifth. */
fun stepStateWord(phase: StepPhase): String = when (phase) {
    StepPhase.DONE -> "done"
    StepPhase.ACTIVE -> "running"
    StepPhase.PENDING -> "queued"
}

/**
 * Staged, honest progress: named steps with the real stage detail and the real
 * percentage from [com.flutterguard.app.scan.ScanState]. No spinner, no
 * fabricated percentage; animation is a calm color transition and is switched
 * off when the system disables animators.
 */
@Composable
fun ScanStepper(
    stage: String,
    pct: Int,
    modifier: Modifier = Modifier,
) {
    val state = remember(stage, pct) { ScanStepper.of(stage, pct) }
    val motion = remember { ValueAnimator.areAnimatorsEnabled() }
    val spec = tween<androidx.compose.ui.graphics.Color>(durationMillis = if (motion) 220 else 0)
    val activeColor = animateColorAsState(
        targetValue = MaterialTheme.colorScheme.primary,
        animationSpec = spec,
        label = "stepper-accent",
    ).value

    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(Space.xs)) {
        LinearProgressIndicator(
            progress = { state.pct / 100f },
            modifier = Modifier.fillMaxWidth(),
        )
        // One live region for the whole stepper, on the stage name only: the
        // percentage changes on every callback and must never be announced.
        Text(
            state.activeLabel,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
        Text(
            "${state.pct}%",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.size(Space.xs))
        state.steps.forEachIndexed { index, step ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                val dotColor = when (step.phase) {
                    StepPhase.DONE -> MaterialTheme.colorScheme.onSurfaceVariant
                    StepPhase.ACTIVE -> activeColor
                    StepPhase.PENDING -> MaterialTheme.colorScheme.outlineVariant
                }
                Surface(color = dotColor, shape = CircleShape, modifier = Modifier.size(8.dp)) {}
                Spacer(Modifier.width(Space.s))
                Text(
                    "${index + 1}. ${step.label}",
                    style = if (step.phase == StepPhase.ACTIVE) {
                        MaterialTheme.typography.bodyMedium
                    } else {
                        MaterialTheme.typography.bodySmall
                    },
                    color = when (step.phase) {
                        StepPhase.PENDING -> MaterialTheme.colorScheme.onSurfaceVariant
                        else -> MaterialTheme.colorScheme.onSurface
                    },
                    modifier = Modifier.weight(1f),
                )
                Text(
                    stepStateWord(step.phase),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
