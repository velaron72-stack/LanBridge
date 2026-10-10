package app.lanbridge.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LightColors = lightColorScheme(
    primary = Color(0xFF0B6E7F),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFCFEAF0),
    onPrimaryContainer = Color(0xFF05303A),
    secondary = Color(0xFF4B6469),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFDDE8EB),
    onSecondaryContainer = Color(0xFF16272B),
    tertiary = Color(0xFF8A5A00),
    onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFF4F7F9),
    onBackground = Color(0xFF12202B),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF12202B),
    surfaceVariant = Color(0xFFE6EDF1),
    onSurfaceVariant = Color(0xFF3F4C55),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF8FAFB),
    surfaceContainer = Color(0xFFF1F5F7),
    surfaceContainerHigh = Color(0xFFEBF0F3),
    surfaceContainerHighest = Color(0xFFE6EDF1),
    outline = Color(0xFF73828C),
    outlineVariant = Color(0xFFCAD4DA),
    error = Color(0xFFB3261E),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFF9DEDC),
    onErrorContainer = Color(0xFF410E0B),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF63C7D8),
    onPrimary = Color(0xFF00363F),
    primaryContainer = Color(0xFF004F5C),
    onPrimaryContainer = Color(0xFFCFEAF0),
    secondary = Color(0xFFB1C9CE),
    onSecondary = Color(0xFF1C3438),
    secondaryContainer = Color(0xFF334B50),
    onSecondaryContainer = Color(0xFFDDE8EB),
    tertiary = Color(0xFFE6B450),
    onTertiary = Color(0xFF3F2A00),
    background = Color(0xFF0E171E),
    onBackground = Color(0xFFE3EBF0),
    surface = Color(0xFF16222B),
    onSurface = Color(0xFFE3EBF0),
    surfaceVariant = Color(0xFF223039),
    onSurfaceVariant = Color(0xFFB4C2CB),
    surfaceContainerLowest = Color(0xFF0A1218),
    surfaceContainerLow = Color(0xFF121D25),
    surfaceContainer = Color(0xFF16222B),
    surfaceContainerHigh = Color(0xFF1D2B35),
    surfaceContainerHighest = Color(0xFF243440),
    outline = Color(0xFF86949E),
    outlineVariant = Color(0xFF384852),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

@Composable
fun LanBridgeTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        typography = Typography(),
        content = content,
    )
}

@Composable
fun okColor(): Color = if (isSystemInDarkTheme()) Color(0xFF58C896) else Color(0xFF1B7F52)

@Composable
fun warnColor(): Color = if (isSystemInDarkTheme()) Color(0xFFE6B450) else Color(0xFF8A5A00)
