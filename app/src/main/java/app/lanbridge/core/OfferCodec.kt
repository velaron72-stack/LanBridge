package app.lanbridge.core

import android.util.Base64

/**
 * Text form of a connection code: "LB2-" + base64url(binary offer) for a direct connection of two devices and
 * "LBG-" + base64url(binary offer) for a group code. Codes of the 1.x versions start with "LB1-".
 * The prefix is only a hint for the reader: the core decides what a code is from its content.
 *
 * A code travels through chats, notes and keyboards, which wrap long words, add spaces, swap "-" for a typographic
 * dash, put in invisible characters and change the case of the first letter. [candidates] undoes all of that; since
 * the core checks the length and the checksum of a code, the reader can try every plausible reading and keep the
 * one that is valid.
 */
object OfferCodec {
    const val PREFIX = "LB2-"
    const val GROUP_PREFIX = "LBG-"
    private const val LEGACY_PREFIX = "LB1-"
    private const val FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

    /** Shortest text that can hold a code (the core needs 50 bytes at least). */
    private const val MIN_CHARS = 40

    /** Longest code that is worth reading, and how many pieces of a code that was split are joined at most. */
    private const val MAX_CHARS = 4096
    private const val MAX_PIECES = 24

    fun encode(blob: ByteArray): String = PREFIX + Base64.encodeToString(blob, FLAGS)

    fun encodeGroup(blob: ByteArray): String = GROUP_PREFIX + Base64.encodeToString(blob, FLAGS)

    /** True if the text holds a code made by version 1.x of the app (it cannot be used any more). */
    fun isLegacy(text: String): Boolean {
        val t = normalize(text)
        return t.contains(LEGACY_PREFIX, ignoreCase = true) &&
            !t.contains(PREFIX, ignoreCase = true) && !t.contains(GROUP_PREFIX, ignoreCase = true)
    }

    /** One reading of a pasted text: the decoded bytes and the number of characters of the code that were read. */
    class Reading(val blob: ByteArray, val chars: Int)

    /**
     * Every plausible reading of a code found in [text], most likely first: for each prefix, the text up to the first
     * space, then that and the next piece joined (a code split over lines), and so on. If the text holds no prefix
     * at all, the longest run of code characters is tried as a code that lost its prefix.
     */
    fun candidates(text: String): List<Reading> {
        val t = normalize(text)
        val out = ArrayList<Reading>()
        var found = false
        var from = 0
        while (from < t.length && out.size < 64) {
            val a = t.indexOf(PREFIX, from, ignoreCase = true)
            val b = t.indexOf(GROUP_PREFIX, from, ignoreCase = true)
            val start = when {
                a < 0 -> b
                b < 0 -> a
                else -> minOf(a, b)
            }
            if (start < 0) break
            found = true
            val end = readPieces(t, start + PREFIX.length, out)
            from = maxOf(end, start + PREFIX.length)
        }
        if (!found) {
            // A code without its prefix: the longest run of code characters.
            var best = ""
            for (run in Regex("[A-Za-z0-9_+/\\-]{$MIN_CHARS,}").findAll(t)) {
                if (run.value.length > best.length) best = run.value
            }
            if (best.isNotEmpty()) add(out, best.replace('+', '-').replace('/', '_'))
        }
        return out
    }

    /** The first reading, or null. */
    fun extract(text: String): ByteArray? = candidates(text).firstOrNull()?.blob

    /**
     * Reads the pieces of a code that follow the prefix, from [pos]: runs of code characters separated by white space,
     * up to the first character that cannot belong to a code. Adds one candidate for every number of pieces.
     * Returns the index where the reading stopped.
     */
    private fun readPieces(t: String, pos: Int, out: MutableList<Reading>): Int {
        val pieces = ArrayList<String>()
        val starts = ArrayList<Int>()
        val cur = StringBuilder()
        var curStart = pos
        var i = pos
        var stop = false
        while (i < t.length && !stop) {
            val c = t[i]
            val isCode = (c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '-' || c == '_' || c == '+' || c == '/'
            when {
                isCode -> {
                    if (cur.isEmpty()) curStart = i
                    cur.append(if (c == '+') '-' else if (c == '/') '_' else c)
                }
                c == '=' -> {}
                c == ' ' || c == '\n' || c == '\r' || c == '\t' -> {
                    if (cur.isNotEmpty()) {
                        pieces.add(cur.toString())
                        starts.add(curStart)
                        cur.setLength(0)
                        if (pieces.size >= MAX_PIECES) stop = true
                    }
                }
                else -> stop = true
            }
            if (!stop) i++
        }
        if (cur.isNotEmpty()) {
            pieces.add(cur.toString())
            starts.add(curStart)
        }
        val joined = StringBuilder()
        for ((k, p) in pieces.withIndex()) {
            // A piece that starts a new code belongs to that code: reading goes on from there.
            if (k > 0 && (p.startsWith(PREFIX, true) || p.startsWith(GROUP_PREFIX, true))) return starts[k]
            joined.append(p)
            if (joined.length > MAX_CHARS) break
            add(out, joined.toString())
        }
        return i
    }

    private fun add(out: MutableList<Reading>, body: String) {
        if (body.length < MIN_CHARS) return
        val blob = try {
            Base64.decode(body, FLAGS)
        } catch (e: IllegalArgumentException) {
            return
        }
        out.add(Reading(blob, body.length))
    }

    /** Typographic dashes become "-", invisible characters go, odd spaces become " ". */
    private fun normalize(text: String): String {
        val sb = StringBuilder(text.length)
        for (c in text) {
            when {
                c in '‐'..'―' || c == '−' || c == '﹘' || c == '﹣' || c == '－' -> sb.append('-')
                c in '​'..'‏' || c in '‪'..'‮' || c == '⁠' || c == '﻿' || c == '­' -> {}
                c == ' ' || c == ' ' || c == ' ' || c == '　' || c == ' ' || c == ' ' -> sb.append(' ')
                else -> sb.append(c)
            }
        }
        return sb.toString()
    }
}
