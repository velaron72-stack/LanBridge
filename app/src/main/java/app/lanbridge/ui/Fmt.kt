package app.lanbridge.ui

import app.lanbridge.core.Member
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

    /** "host:1.2.3.4:5000" -> "локальный 1.2.3.4:5000"; "srflx:[2001:db8::1]:5000" -> "внешний IPv6 [2001:db8::1]:5000" */
    fun cand(c: String): String {
        val i = c.indexOf(':')
        if (i < 0) return c
        val kind = c.substring(0, i)
        val rest = c.substring(i + 1)
        val v6 = rest.startsWith("[")
        val label = when {
            kind == "host" && v6 -> "адрес IPv6 "
            kind == "host" -> "локальный "
            v6 -> "внешний IPv6 "
            else -> "внешний "
        }
        return label + rest
    }

    /** A member of the network as the list shows it: the name, or "Участник N" while the profile has not arrived yet. */
    fun memberName(m: Member): String = m.name.ifBlank { "Участник ${m.slot}" }

    fun memberState(state: Int): String = when (state) {
        1 -> "соединяется"
        2 -> "в сети"
        3 -> "не отвечает"
        4 -> "вышел"
        else -> "—"
    }

    /** How the packets of a member travel: 0 none, 1 internet, 2 local network, 3 through the creator. */
    fun memberPath(kind: Int): String = when (kind) {
        1 -> "напрямую через интернет"
        2 -> "напрямую, локальная сеть"
        3 -> "через создателя группы"
        else -> ""
    }

    /** "в сети · 23 мс · напрямую через интернет", the second line of a member row. */
    fun memberLine(m: Member): String {
        val parts = ArrayList<String>()
        parts.add(memberState(m.state))
        if (m.state == 2 && m.rttMs >= 0) parts.add("${m.rttMs} мс")
        val p = memberPath(m.pathKind)
        if (m.state == 2 && p.isNotEmpty()) parts.add(p)
        if (m.state == 2 && m.pathText.isNotEmpty() && m.pathKind != 3) parts.add(if (m.pathText.startsWith("[")) "IPv6" else "IPv4")
        return parts.joinToString(" · ")
    }

    /** Protocols a code can be reached over: bit 0 IPv4, bit 1 IPv6. */
    fun families(f: Int): String = when (f) {
        3 -> "IPv4 и IPv6"
        2 -> "только IPv6"
        1 -> "только IPv4"
        else -> "нет адресов"
    }
}
