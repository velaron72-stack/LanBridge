package androidx.compose.ui.platform

import android.content.Context
import androidx.compose.runtime.staticCompositionLocalOf

/** The shared screens ask for a Context to copy, paste and read settings; on the desktop it is the one process context. */
val LocalContext = staticCompositionLocalOf { Context() }
