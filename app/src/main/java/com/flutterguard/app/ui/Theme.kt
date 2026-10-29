package com.flutterguard.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Semantic cool-neutral palette with one cyan accent, derived from the same
 * roles in both themes. No gradients, no hardcoded component colors: every
 * screen reads these tokens so light/dark and large text stay coherent.
 */
private val LightColors = lightColorScheme(
    primary = Color(0xFF006874),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF97F0FF),
    onPrimaryContainer = Color(0xFF001F24),
    secondary = Color(0xFF4A6267),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFCDE7EC),
    onSecondaryContainer = Color(0xFF051F23),
    tertiary = Color(0xFF4F5F7E),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFD7E3FF),
    onTertiaryContainer = Color(0xFF071B36),
    background = Color(0xFFF5FAFA),
    onBackground = Color(0xFF171D1E),
    surface = Color(0xFFF5FAFA),
    onSurface = Color(0xFF171D1E),
    surfaceVariant = Color(0xFFDAE4E6),
    onSurfaceVariant = Color(0xFF3F484A),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFEFF4F5),
    surfaceContainer = Color(0xFFE9EFF0),
    surfaceContainerHigh = Color(0xFFE3E9EA),
    surfaceContainerHighest = Color(0xFFDDE4E5),
    outline = Color(0xFF6F797A),
    outlineVariant = Color(0xFFBEC8CA),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    inverseSurface = Color(0xFF2B3133),
    inverseOnSurface = Color(0xFFECF2F3),
    inversePrimary = Color(0xFF4DD9E8),
    scrim = Color(0xFF000000),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF4DD9E8),
    onPrimary = Color(0xFF00363D),
    primaryContainer = Color(0xFF004F58),
    onPrimaryContainer = Color(0xFF97F0FF),
    secondary = Color(0xFFB1CBD0),
    onSecondary = Color(0xFF1C3438),
    secondaryContainer = Color(0xFF334B4F),
    onSecondaryContainer = Color(0xFFCDE7EC),
    tertiary = Color(0xFFB7C7EA),
    onTertiary = Color(0xFF20314D),
    tertiaryContainer = Color(0xFF374765),
    onTertiaryContainer = Color(0xFFD7E3FF),
    background = Color(0xFF0E1416),
    onBackground = Color(0xFFDDE4E5),
    surface = Color(0xFF0E1416),
    onSurface = Color(0xFFDDE4E5),
    surfaceVariant = Color(0xFF3F484A),
    onSurfaceVariant = Color(0xFFBEC8CA),
    surfaceContainerLowest = Color(0xFF090F11),
    surfaceContainerLow = Color(0xFF171D1E),
    surfaceContainer = Color(0xFF1B2122),
    surfaceContainerHigh = Color(0xFF252B2C),
    surfaceContainerHighest = Color(0xFF303637),
    outline = Color(0xFF899395),
    outlineVariant = Color(0xFF3F484A),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    inverseSurface = Color(0xFFDDE4E5),
    inverseOnSurface = Color(0xFF2B3133),
    inversePrimary = Color(0xFF006874),
    scrim = Color(0xFF000000),
)

/**
 * One radius family. Cards, rows, banners and dialogs share `medium`; inputs and
 * inline badges `extraSmall`; chips/actions `extraLarge` — equal to `medium` on
 * purpose, so a chip can never grow back into a 28 dp pill. `large` is for
 * bottom sheets only (none render today). This is the only file allowed to name
 * a corner radius.
 */
private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(12.dp),
)

private val Base = Typography()

/**
 * One type role per job, so no call site invents a size. Sizes follow the 4 dp
 * rhythm and stay legible at 1.3× font scale.
 */
private val AppTypography = Typography(
    displaySmall = Base.displaySmall.copy(fontSize = 34.sp, lineHeight = 40.sp), // grade letter
    headlineMedium = Base.headlineMedium.copy(fontSize = 26.sp, lineHeight = 32.sp), // stat number
    titleLarge = Base.titleLarge.copy(fontSize = 20.sp, lineHeight = 26.sp, fontWeight = FontWeight.SemiBold),
    titleMedium = Base.titleMedium.copy(fontSize = 16.sp, lineHeight = 24.sp, fontWeight = FontWeight.Medium),
    titleSmall = Base.titleSmall.copy(fontSize = 14.sp, lineHeight = 20.sp, fontWeight = FontWeight.Medium),
    bodyMedium = Base.bodyMedium.copy(fontSize = 14.sp, lineHeight = 20.sp),
    bodySmall = Base.bodySmall.copy(fontSize = 13.sp, lineHeight = 18.sp), // metadata, mono values
    labelLarge = Base.labelLarge.copy(fontSize = 14.sp, lineHeight = 20.sp, fontWeight = FontWeight.Medium),
    labelSmall = Base.labelSmall.copy(fontSize = 11.sp, lineHeight = 16.sp), // state words, counters
)

@Composable
fun FlutterGuardTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        shapes = AppShapes,
        typography = AppTypography,
        content = content,
    )
}
