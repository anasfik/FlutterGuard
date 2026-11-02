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
 * Semantic porcelain/forest/mint palette shared with the website family.
 * One roleset per theme, derived from the same site tokens in both themes.
 * No gradients, no hardcoded component colors: every screen reads these
 * tokens so light/dark and large text stay coherent.
 */
private val LightColors = lightColorScheme(
    primary = Color(0xFF285F42),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFBCE6A0),
    onPrimaryContainer = Color(0xFF132D25),
    secondary = Color(0xFF53675B),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFCED9CC),
    onSecondaryContainer = Color(0xFF132D25),
    tertiary = Color(0xFF4F5F7E),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFD7E3FF),
    onTertiaryContainer = Color(0xFF071B36),
    background = Color(0xFFF3F5EF),
    onBackground = Color(0xFF132D25),
    surface = Color(0xFFFAFBF7),
    onSurface = Color(0xFF132D25),
    surfaceVariant = Color(0xFFDFE6D2),
    onSurfaceVariant = Color(0xFF53675B),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF1F4EA),
    surfaceContainer = Color(0xFFE9EDDF),
    surfaceContainerHigh = Color(0xFFDFE5D2),
    surfaceContainerHighest = Color(0xFFD3D9C4),
    outline = Color(0xFF6E7B6E),
    outlineVariant = Color(0xFFCED9CC),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    inverseSurface = Color(0xFF232B24),
    inverseOnSurface = Color(0xFFECF2E6),
    inversePrimary = Color(0xFFBCE6A0),
    scrim = Color(0xFF000000),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFBCE6A0),
    onPrimary = Color(0xFF132D25),
    primaryContainer = Color(0xFF285F42),
    onPrimaryContainer = Color(0xFFD9EAD0),
    secondary = Color(0xFF9DB4A0),
    onSecondary = Color(0xFF132D25),
    secondaryContainer = Color(0xFF24382C),
    onSecondaryContainer = Color(0xFFCED9CC),
    tertiary = Color(0xFFB7C7EA),
    onTertiary = Color(0xFF20314D),
    tertiaryContainer = Color(0xFF374765),
    onTertiaryContainer = Color(0xFFD7E3FF),
    background = Color(0xFF101815),
    onBackground = Color(0xFFDDE5DA),
    surface = Color(0xFF101815),
    onSurface = Color(0xFFDDE5DA),
    surfaceVariant = Color(0xFF3A453C),
    onSurfaceVariant = Color(0xFFB9C4B6),
    surfaceContainerLowest = Color(0xFF0B100D),
    surfaceContainerLow = Color(0xFF141B16),
    surfaceContainer = Color(0xFF1A221B),
    surfaceContainerHigh = Color(0xFF212A22),
    surfaceContainerHighest = Color(0xFF293329),
    outline = Color(0xFF8A968A),
    outlineVariant = Color(0xFF2A352B),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    inverseSurface = Color(0xFFDDE5DA),
    inverseOnSurface = Color(0xFF232B24),
    inversePrimary = Color(0xFF285F42),
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
