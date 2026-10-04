package app.lanbridge.ui

import java.util.Locale

object Fmt {
    fun bytes(n: Long): String {
        if (n < 1024L) return "$n Б"
        val kb = n / 1024.0
        if (kb < 1024.0) return String.format(Locale.US, "%.1f КБ", kb)
        val mb = kb / 1024.0
        if (mb < 1024.0) return String.format(Locale.US, "%.1f МБ", mb)
        return String.format(Locale.US, "%.2f ГБ", mb / 1024.0)
    }

    fun duration(sec: Long): String {
        val s = if (sec < 0) 0L else sec
        val h = s / 3600
        val m = (s % 3600) / 60
        val r = s % 60
        return if (h > 0) String.format(Locale.US, "%d:%02d:%02d", h, m, r) else String.format(Locale.US, "%02d:%02d", m, r)
    }

    /** Time left until a code expires, or null if it already has. */
    fun remaining(expiresAtSec: Long, nowMs: Long): String? {
        val left = expiresAtSec - nowMs / 1000
        if (left <= 0) return null
        return duration(left)
    }

    fun nat(n: Int): String = when (n) {
        1 -> "конусный (прямое соединение вероятно)"
        2 -> "симметричный (прямое соединение маловероятно)"
        else -> "не определён"
    }

    /** "host:1.2.3.4:5000" -> "локальный 1.2.3.4:5000" */
    fun cand(c: String): String {
        val i = c.indexOf(':')
        if (i < 0) return c
        val kind = c.substring(0, i)
        val rest = c.substring(i + 1)
        return (if (kind == "host") "локальный " else "внешний ") + rest
    }
}
