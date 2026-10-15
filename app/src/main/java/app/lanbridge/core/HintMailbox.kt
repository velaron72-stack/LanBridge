package app.lanbridge.core

import android.util.Base64
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

/**
 * Optional help for a group whose creator sits behind a strict NAT. Such a NAT drops the first packets of a newcomer
 * until the creator has sent something to the newcomer's address, and the creator only learns that address from the
 * newcomer. The newcomer therefore leaves a small note on a public message board (ntfy.sh) and the creator reads it.
 *
 * The note is sealed by the core with a key derived from the group code (it holds nothing but the newcomer's network
 * addresses) and the topic name is derived from the code as well. Everything here is best effort: when the board cannot
 * be reached the group still works whenever the NAT allows it, and no error is ever shown for it.
 */
object HintMailbox {
    private const val BASE = "https://ntfy.sh/"
    private const val FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
    private val seen = LinkedHashSet<String>()

    private fun topicOk(topic: String): Boolean = topic.length in 8..64 && topic.all { it.isLetterOrDigit() || it == '_' || it == '-' }

    @Synchronized
    fun reset() {
        seen.clear()
    }

    /** Puts a note on the board. */
    fun post(topic: String, note: ByteArray): Boolean {
        if (!topicOk(topic) || note.isEmpty()) return false
        var c: HttpURLConnection? = null
        return try {
            c = URL(BASE + topic).openConnection() as HttpURLConnection
            c.connectTimeout = 4000
            c.readTimeout = 4000
            c.requestMethod = "POST"
            c.doOutput = true
            c.setRequestProperty("Content-Type", "text/plain; charset=utf-8")
            val body = Base64.encodeToString(note, FLAGS).toByteArray(Charsets.US_ASCII)
            c.outputStream.use { it.write(body) }
            c.responseCode in 200..299
        } catch (_: Exception) {
            false
        } finally {
            try {
                c?.disconnect()
            } catch (_: Exception) {
            }
        }
    }

    /** The notes that appeared on the board since the previous call (each note is returned once). */
    fun fetch(topic: String): List<ByteArray> {
        if (!topicOk(topic)) return emptyList()
        val out = ArrayList<ByteArray>()
        var c: HttpURLConnection? = null
        try {
            c = URL(BASE + topic + "/json?poll=1&since=5m").openConnection() as HttpURLConnection
            c.connectTimeout = 4000
            c.readTimeout = 5000
            c.requestMethod = "GET"
            if (c.responseCode !in 200..299) return out
            val lines = BufferedReader(InputStreamReader(c.inputStream, Charsets.UTF_8)).use { it.readLines() }
            for (line in lines) {
                if (line.isBlank()) continue
                val o = try {
                    JSONObject(line)
                } catch (_: Exception) {
                    continue
                }
                if (o.optString("event") != "message") continue
                val id = o.optString("id")
                if (id.isEmpty() || !markSeen(id)) continue
                val msg = o.optString("message").trim()
                if (msg.isEmpty() || msg.length > 400) continue
                try {
                    out.add(Base64.decode(msg, FLAGS))
                } catch (_: IllegalArgumentException) {
                }
            }
        } catch (_: Exception) {
        } finally {
            try {
                c?.disconnect()
            } catch (_: Exception) {
            }
        }
        return out
    }

    @Synchronized
    private fun markSeen(id: String): Boolean {
        if (!seen.add(id)) return false
        while (seen.size > 300) seen.remove(seen.first())
        return true
    }
}
