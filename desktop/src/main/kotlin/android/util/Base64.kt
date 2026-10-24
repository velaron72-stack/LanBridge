package android.util

/** The flags and the two calls of android.util.Base64 that the shared code uses, on top of java.util.Base64. */
object Base64 {
    const val DEFAULT = 0
    const val NO_PADDING = 1
    const val NO_WRAP = 2
    const val CRLF = 4
    const val URL_SAFE = 8

    fun encodeToString(input: ByteArray, flags: Int): String {
        var enc = if (flags and URL_SAFE != 0) java.util.Base64.getUrlEncoder() else java.util.Base64.getEncoder()
        if (flags and NO_PADDING != 0) enc = enc.withoutPadding()
        return enc.encodeToString(input)
    }

    /** Throws IllegalArgumentException for text that is not Base64, like the Android one. Missing padding is accepted. */
    fun decode(str: String, flags: Int): ByteArray {
        val dec = if (flags and URL_SAFE != 0) java.util.Base64.getUrlDecoder() else java.util.Base64.getDecoder()
        return dec.decode(str)
    }
}
