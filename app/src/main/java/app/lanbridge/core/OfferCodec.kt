package app.lanbridge.core

import android.util.Base64

/** Text form of a connection code: "LB1-" + base64url(binary offer). */
object OfferCodec {
    const val PREFIX = "LB1-"
    private const val FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

    fun encode(blob: ByteArray): String = PREFIX + Base64.encodeToString(blob, FLAGS)

    /** Finds a code anywhere inside pasted text (for example a whole chat message). */
    fun extract(text: String): ByteArray? {
        val start = text.indexOf(PREFIX)
        if (start < 0) return null
        var i = start + PREFIX.length
        val sb = StringBuilder()
        while (i < text.length) {
            val c = text[i]
            if ((c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '-' || c == '_') sb.append(c) else break
            i++
        }
        if (sb.length < 40) return null
        return try {
            Base64.decode(sb.toString(), FLAGS)
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}
