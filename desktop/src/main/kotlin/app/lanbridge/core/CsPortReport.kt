package app.lanbridge.core

/**
 * For the "Проверка LAN" report on the PC: which programs listen on the UDP ports where a Half-Life / CS 1.6 / Xash3D
 * server waits for the server browser (27015–27024), and on which address. A server bound to one address of the
 * computer (not 0.0.0.0) does not receive the packets that arrive through the virtual adapter.
 */
object CsPortReport {
    private val PORTS = 27015..27024

    /** Replaced in tests. */
    @Volatile
    internal var runner: (String, Int) -> Pair<Int, String> = { cmd, timeout -> WinTun.exec(cmd, timeout) }

    @Volatile
    internal var system32: (String) -> String = { WinTun.system32(it) }

    class Listener(val address: String, val port: Int, val pid: Int)

    /** The lines of "netstat -ano -p udp": local address, port and process of every UDP socket on the game ports. */
    internal fun parse(out: String): List<Listener> {
        val res = ArrayList<Listener>()
        val re = Regex("^\\s*UDP\\s+(\\S+):(\\d+)\\s+\\*:\\*\\s+(\\d+)\\s*$", RegexOption.IGNORE_CASE)
        for (line in out.lineSequence()) {
            val m = re.find(line) ?: continue
            val port = m.groupValues[2].toIntOrNull() ?: continue
            if (port !in PORTS) continue
            res.add(Listener(m.groupValues[1], port, m.groupValues[3].toIntOrNull() ?: continue))
        }
        return res
    }

    /** First field of "tasklist /FO CSV /NH": "hl.exe","1234",... */
    internal fun parseName(out: String): String? =
        Regex("^\"([^\"]+)\"").find(out.lineSequence().firstOrNull { it.startsWith("\"") } ?: "")?.groupValues?.get(1)

    internal fun format(listeners: List<Listener>, nameOf: (Int) -> String?): String {
        val head = "Порты UDP ${PORTS.first}–${PORTS.last} на этом компьютере"
        if (listeners.isEmpty()) {
            return "$head: никто не слушает. Если здесь должен быть сервер CS, он не создан или работает на другом порту."
        }
        val sb = StringBuilder("$head:")
        var specific = false
        for (l in listeners) {
            val name = nameOf(l.pid)
            sb.append("\n  ").append(l.address).append(':').append(l.port).append(" — ")
                .append(if (name != null) "$name (PID ${l.pid})" else "PID ${l.pid}")
            if (l.address != "0.0.0.0") specific = true
        }
        if (specific) {
            sb.append("\n  Сервер привязан к одному адресу, а не ко всем (0.0.0.0): пакеты, пришедшие через адаптер LanBridge на другой адрес, он не получит. ")
                .append("Запустите сервер без параметра +ip или с +ip 0.0.0.0.")
        }
        return sb.toString()
    }

    fun run(): String {
        val (code, out) = runner("\"${system32("netstat.exe")}\" -ano -p udp", 15000)
        if (code != 0) return "Порты UDP ${PORTS.first}–${PORTS.last}: netstat не выполнен (код $code)"
        val listeners = parse(out)
        val names = HashMap<Int, String?>()
        return format(listeners) { pid ->
            names.getOrPut(pid) {
                val (c, o) = runner("\"${system32("tasklist.exe")}\" /FI \"PID eq $pid\" /FO CSV /NH", 15000)
                if (c == 0) parseName(o) else null
            }
        }
    }
}
