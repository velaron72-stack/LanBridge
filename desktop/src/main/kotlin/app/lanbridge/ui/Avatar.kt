package app.lanbridge.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.sp

private val AVATAR_COLORS = longArrayOf(
    0xFF0B6E7F, 0xFF7A4DB3, 0xFFB5543A, 0xFF3F7F3A, 0xFF9A6A00, 0xFF2F5FA8, 0xFFA83F6E, 0xFF5C6B73,
)

/** The color of the circle that stands in for a missing picture: the same name always gets the same color. */
fun avatarColor(name: String): Color {
    var h = 0
    for (ch in name) h = h * 31 + ch.code
    val i = ((h % AVATAR_COLORS.size) + AVATAR_COLORS.size) % AVATAR_COLORS.size
    return Color(AVATAR_COLORS[i])
}

/** The first letter or digit of a name, in capitals; "?" when there is none. */
fun initialOf(name: String): String {
    val t = name.trim()
    var i = 0
    while (i < t.length) {
        val cp = t.codePointAt(i)
        if (Character.isLetterOrDigit(cp)) return String(Character.toChars(cp)).uppercase()
        i += Character.charCount(cp)
    }
    return "?"
}

private fun decodeAvatar(bytes: ByteArray?): ImageBitmap? {
    if (bytes == null || bytes.isEmpty()) return null
    return try {
        org.jetbrains.skia.Image.makeFromEncoded(bytes).toComposeImageBitmap()
    } catch (_: Throwable) {
        null
    }
}

/** A round avatar: the picture of the participant, or a colored circle with the initial of the name. */
@Composable
fun AvatarView(name: String, bytes: ByteArray?, size: Dp, modifier: Modifier = Modifier) {
    val bmp = remember(bytes) { decodeAvatar(bytes) }
    if (bmp != null) {
        Image(
            bitmap = bmp,
            contentDescription = name,
            contentScale = ContentScale.Crop,
            modifier = modifier
                .size(size)
                .clip(CircleShape),
        )
    } else {
        Box(
            modifier = modifier
                .size(size)
                .clip(CircleShape)
                .background(avatarColor(name)),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                initialOf(name),
                color = Color.White,
                fontWeight = FontWeight.SemiBold,
                fontSize = (size.value * 0.42f).sp,
            )
        }
    }
}
