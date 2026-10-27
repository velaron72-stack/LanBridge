package app.lanbridge.core

import android.os.SystemClock
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.util.Locale
import java.util.zip.CRC32

/**
 * Real-socket check of the virtual LAN. While the tunnel is up every device answers probes on port 41377
 * (UDP and TCP). "Проверка LAN" sends them to the friend and reports what came back: unicast to the virtual and to the
 * mirrored real address (IPv4 and IPv6), limited and directed broadcast, multicast, UDP datagrams that the tunnel
 * has to cut into chunks or the network stack has to fragment, and a TCP transfer. The result shows which kinds of
 * traffic really cross the tunnel. It also asks the other device the way the server list of a GoldSrc / Xash3D game
 * does (see [GAME_PORTS]) and says whether a game server answers there.
 */
object LanSelfTest {
    const val PORT = 41377

    /** The ports a Half-Life / CS 1.6 / Xash3D server browser asks on the LAN: the default server port and the nine after it. */
    private val GAME_PORTS = 27015..27024

    /** Query of the Source / GoldSrc server browser ("A2S_INFO") and of the Xash3D LAN browser ("info" + protocol 49). */
    private val A2S_INFO = byteArrayOf(-1, -1, -1, -1) + "TSource Engine Query".toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
    private val XASH_INFO = byteArrayOf(-1, -1, -1, -1) + "info 49".toByteArray(Charsets.US_ASCII)

    /** Extra lines for the end of the report from the platform (the PC lists the programs that listen on the game ports). */
    @Volatile
    var extraReport: (() -> String)? = null
    private const val MCAST = "239.255.77.77"
    private const val BIG = 4000
    private const val MID = 1400
    private const val TCP_BYTES = 256 * 1024

    private var responder: Responder? = null

    @Synchronized
    fun startResponder(layout: NetLayout, name: String) {
        stopResponder()
        val r = Responder(layout, name)
        responder = r
        r.start()
    }

    @Synchronized
    fun stopResponder() {
        responder?.shutdown()
        responder = null
    }

    private fun findIface(ip: String): NetworkInterface? = try {
        NetworkInterface.getByInetAddress(InetAddress.getByName(ip))
    } catch (e: Exception) {
        null
    }

    private fun isSelf(layout: NetLayout, addr: String?): Boolean {
        if (addr == null) return false
        if (addr == layout.my || layout.realMine.contains(addr)) return true
        if (layout.my6.isEmpty() || !addr.contains(':')) return false
        val c = NetInfo.canon(addr)
        return c == NetInfo.canon(layout.my6) || layout.realMine6.any { NetInfo.canon(it) == c }
    }

    private fun bodyOf(size: Int): ByteArray = ByteArray(size) { (it % 251).toByte() }

    private fun crcOf(b: ByteArray): Long {
        val c = CRC32()
        c.update(b)
        return c.value
    }

    private class Responder(val layout: NetLayout, val devName: String) : Thread("lanbridge-responder") {
        @Volatile
        private var closed = false

        @Volatile
        private var udp: MulticastSocket? = null

        @Volatile
        private var tcp: ServerSocket? = null

        init {
            isDaemon = true
        }

        fun shutdown() {
            closed = true
            try {
                udp?.close()
            } catch (_: Exception) {
            }
            try {
                tcp?.close()
            } catch (_: Exception) {
            }
        }

        override fun run() {
            val t = Thread({ runTcp() }, "lanbridge-responder-tcp")
            t.isDaemon = true
            t.start()
            runUdp()
        }

        private fun runTcp() {
            try {
                val ss = ServerSocket(PORT)
                tcp = ss
                while (!closed) {
                    val c = ss.accept()
                    val h = Thread({ serveTcp(c) }, "lanbridge-responder-conn")
                    h.isDaemon = true
                    h.start()
                }
            } catch (e: Exception) {
                if (!closed) Native.note("проверка: TCP-ответчик остановлен: ${e.message}")
            }
        }

        private fun serveTcp(c: Socket) {
            try {
                c.use { s ->
                    s.soTimeout = 10000
                    val input = s.getInputStream()
                    val header = StringBuilder()
                    while (header.length < 40) {
                        val b = input.read()
                        if (b < 0 || b == '\n'.code) break
                        header.append(b.toChar())
                    }
                    val parts = header.toString().split(' ')
                    if (parts.size != 2 || parts[0] != "LBX1") return
                    var left = parts[1].toIntOrNull() ?: return
                    if (left < 0 || left > (4 shl 20)) return
                    val crc = CRC32()
                    val buf = ByteArray(16384)
                    while (left > 0) {
                        val n = input.read(buf, 0, minOf(buf.size, left))
                        if (n < 0) return
                        crc.update(buf, 0, n)
                        left -= n
                    }
                    s.getOutputStream().write("OK ${crc.value}\n".toByteArray(Charsets.UTF_8))
                    s.getOutputStream().flush()
                }
            } catch (_: Exception) {
            }
        }

        private fun runUdp() {
            try {
                val s = MulticastSocket(PORT)
                udp = s
                s.broadcast = true
                try {
                    val group = InetAddress.getByName(MCAST)
                    val ni = findIface(layout.my)
                    if (ni != null) s.joinGroup(InetSocketAddress(group, 0), ni) else s.joinGroup(group)
                } catch (e: Exception) {
                    Native.note("проверка: не удалось войти в multicast-группу: ${e.message}")
                }
                val buf = ByteArray(9000)
                while (!closed) {
                    val p = DatagramPacket(buf, buf.size)
                    s.receive(p)
                    if (isSelf(layout, p.address.hostAddress)) continue
                    val reply = answer(p.data, p.length) ?: continue
                    s.send(DatagramPacket(reply, reply.size, p.address, p.port))
                }
            } catch (e: Exception) {
                if (!closed) Native.note("проверка: ответчик остановлен: ${e.message}")
            }
        }

        /** Request: "LBT1 id key round crc bodyLen\n" + body. Reply: "LBR1 id key round ok|bad name". */
        private fun answer(data: ByteArray, len: Int): ByteArray? {
            var nl = -1
            for (i in 0 until minOf(len, 120)) {
                if (data[i] == '\n'.code.toByte()) {
                    nl = i
                    break
                }
            }
            if (nl < 0) return null
            val h = String(data, 0, nl, Charsets.UTF_8).split(' ')
            if (h.size != 6 || h[0] != "LBT1") return null
            val body = data.copyOfRange(nl + 1, len)
            val good = h[5].toIntOrNull() == body.size && h[4].toLongOrNull() == crcOf(body)
            return "LBR1 ${h[1]} ${h[2]} ${h[3]} ${if (good) "ok" else "bad"} $devName".toByteArray(Charsets.UTF_8)
        }
    }

    /** A packet that arrived at the socket of [via] (the address it was sent to). */
    private class Rx(val pkt: DatagramPacket, val at: Long, val via: String)

    /** One answer of a game server: where it came from, to which query, what it says. */
    private class GameAnswer(val from: String, val port: Int, val viaBroadcast: Boolean, val text: String)

    private fun printable(d: ByteArray, from: Int): String {
        val sb = StringBuilder()
        var i = from
        while (i < d.size && sb.length < 100) {
            val c = d[i].toInt() and 0xFF
            sb.append(if (c in 32..126) c.toChar() else if (c == 10 || c == 0) ' ' else '?')
            i++
        }
        return sb.toString().trim()
    }

    /** Reads an answer to A2S_INFO ("I" of Source, "m" of old GoldSrc, "A" = a challenge is wanted), or a text answer of Xash3D. */
    internal fun describeGameReply(d: ByteArray): String? {
        if (d.size < 6 || d[0] != (-1).toByte() || d[1] != (-1).toByte() || d[2] != (-1).toByte() || d[3] != (-1).toByte()) return null
        var i = 5
        fun str(): String {
            val st = i
            while (i < d.size && d[i] != 0.toByte()) i++
            val r = printable(d.copyOfRange(st, minOf(i, d.size)), 0)
            i++
            return r
        }
        fun byte(): Int = if (i < d.size) (d[i++].toInt() and 0xFF) else 0
        return when (d[4].toInt() and 0xFF) {
            0x49 -> {
                val proto = byte()
                val name = str()
                val map = str()
                str()
                val game = str()
                i += 2
                val pl = byte()
                val mx = byte()
                "ответ Source/GoldSrc: «$name», карта $map, игра $game, игроков $pl/$mx, протокол $proto"
            }
            0x6D -> {
                str()
                val name = str()
                val map = str()
                str()
                val game = str()
                val pl = byte()
                val mx = byte()
                val proto = byte()
                "ответ GoldSrc: «$name», карта $map, игра $game, игроков $pl/$mx, протокол $proto"
            }
            0x41 -> "сервер ответил и просит challenge (новый протокол Source)"
            else -> "ответ: " + printable(d, 4)
        }
    }

    private class Probe(val key: String, val label: String, val host: String, val body: Int, val unicast: Boolean = false) {
        val target: InetAddress by lazy { InetAddress.getByName(host) }  // always an IP literal, never a name lookup
    }

    private fun tcpProbe(host: String): String {
        val data = bodyOf(TCP_BYTES)
        val crc = crcOf(data)
        val t0 = SystemClock.elapsedRealtime()
        return try {
            Socket().use { s ->
                s.tcpNoDelay = true
                s.soTimeout = 8000
                s.connect(InetSocketAddress(host, PORT), 4000)
                val out = s.getOutputStream()
                out.write("LBX1 ${data.size}\n".toByteArray(Charsets.UTF_8))
                out.write(data)
                out.flush()
                val line = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.UTF_8)).readLine()
                val dt = (SystemClock.elapsedRealtime() - t0).coerceAtLeast(1L)
                if (line == "OK $crc") {
                    String.format(Locale.US, "OK, %.1f Мбит/с", data.size * 8.0 / dt / 1000.0)
                } else {
                    "ответ неверный (${line ?: "нет ответа"})"
                }
            }
        } catch (e: Exception) {
            "нет соединения (${e.message ?: e.javaClass.simpleName})"
        }
    }

    private fun gameReport(layout: NetLayout, answers: List<GameAnswer>): String {
        val head = "Сервер игры (CS 1.6 / Xash3D / HL, запрос как у списка LAN, порты ${GAME_PORTS.first}–${GAME_PORTS.last})"
        if (answers.isEmpty()) {
            return "$head — нет ответа. На другом устройстве сервер не создан, не слушает эти порты или принимает пакеты только " +
                "на одном из адресов компьютера. Туннель при этом может быть исправен: сервер отвечает только когда он запущен."
        }
        val sb = StringBuilder("$head:")
        for (a in answers) {
            sb.append("\n  ").append(a.from).append(':').append(a.port).append(if (a.viaBroadcast) " (на широковещательный запрос) — " else " (на прямой запрос) — ").append(a.text)
        }
        val direct = answers.any { !it.viaBroadcast }
        val broad = answers.any { it.viaBroadcast }
        if (direct && !broad) {
            sb.append("\n  Прямой запрос на ${layout.peer} проходит, а широковещательный (как у списка LAN) нет: подключайтесь командой connect ${layout.peer}.")
        } else if (direct && broad) {
            sb.append("\n  Сервер виден и прямым, и широковещательным запросом: в списке LAN он должен появиться.")
        }
        return sb.toString()
    }

    /** Blocking, up to about ten seconds. Call from a background thread. */
    fun run(layout: NetLayout): String {
        val probes = ArrayList<Probe>()
        probes += Probe("u", "Unicast ${layout.peer}", layout.peer, 0, true)
        val real = layout.aliasRoutes.firstOrNull()
        if (real != null) probes += Probe("r", "Unicast $real (реальный адрес участника)", real, 0, true)
        probes += Probe("b1", "Broadcast 255.255.255.255", "255.255.255.255", 0)
        probes += Probe("b2", "Broadcast ${layout.bcast}", layout.bcast, 0)
        probes += Probe("m", "Multicast $MCAST", MCAST, 0)
        probes += Probe("c", "UDP $MID Б (больше 1339: туннель режет сам)", layout.peer, MID, true)
        probes += Probe("f", "UDP $BIG Б (фрагментация IP)", layout.peer, BIG, true)
        val real6 = layout.aliasRoutes6.firstOrNull()
        if (layout.peer6.isNotEmpty()) {
            probes += Probe("u6", "IPv6 unicast ${layout.peer6}", layout.peer6, 0, true)
            if (real6 != null) probes += Probe("r6", "IPv6 unicast $real6 (реальный адрес участника)", real6, 0, true)
            probes += Probe("c6", "IPv6 UDP $MID Б (туннель режет сам)", layout.peer6, MID, true)
            probes += Probe("f6", "IPv6 UDP $BIG Б (фрагментация)", layout.peer6, BIG, true)
        }

        val ok = LinkedHashMap<String, Long>()
        val err = HashMap<String, String>()
        // One socket per address that is probed. The tunnel remembers for every flow (local port, remote address and
        // port) which address of this device the other side wrote to, and answers from it, as IP_PKTINFO would. Two
        // probes from one socket to two addresses of this device (the virtual one and a real one) would be one flow
        // for it, and the replies of the first would come from the address of the second.
        val socks = LinkedHashMap<String, MulticastSocket>()
        val replies = java.util.concurrent.ConcurrentLinkedQueue<Rx>()
        val gameAnswers = ArrayList<GameAnswer>()
        val gameTargets = ArrayList<Pair<String, Boolean>>()  // address, broadcast?
        if (layout.peer.isNotEmpty()) gameTargets += layout.peer to false
        gameTargets += "255.255.255.255" to true
        try {
            val ni = findIface(layout.my)
            for (p in probes) {
                if (socks.containsKey(p.host)) continue
                val sock = MulticastSocket()
                socks[p.host] = sock
                sock.broadcast = true
                if (ni != null) {
                    try {
                        sock.networkInterface = ni
                    } catch (_: Exception) {
                    }
                }
                val via = p.host
                val rx = Thread({
                    val buf = ByteArray(2000)
                    try {
                        while (!sock.isClosed) {
                            val pkt = DatagramPacket(buf, buf.size)
                            sock.receive(pkt)
                            val copy = DatagramPacket(pkt.data.copyOf(pkt.length), pkt.length, pkt.address, pkt.port)
                            replies.add(Rx(copy, SystemClock.elapsedRealtime(), via))
                        }
                    } catch (_: Exception) {
                    }
                }, "lanbridge-check-rx")
                rx.isDaemon = true
                rx.start()
            }
            val id = (SystemClock.elapsedRealtime() % 100000L).toString()
            val sentAt = HashMap<String, Long>()
            val rounds = longArrayOf(0L, 250L, 600L)
            var nextRound = 0
            val t0 = SystemClock.elapsedRealtime()
            while (true) {
                val now = SystemClock.elapsedRealtime()
                // the game servers get time to answer even when every probe of the check has been answered
                if (now - t0 > 3000L || (ok.size >= probes.size && now - t0 > 1200L)) break
                if (nextRound < rounds.size && now - t0 >= rounds[nextRound]) {
                    for (p in probes) {
                        if (ok.containsKey(p.key)) continue
                        val body = bodyOf(p.body)
                        val head = "LBT1 $id ${p.key} $nextRound ${crcOf(body)} ${body.size}\n".toByteArray(Charsets.UTF_8)
                        val data = head + body
                        sentAt["${p.key}#$nextRound"] = SystemClock.elapsedRealtime()
                        try {
                            socks[p.host]?.send(DatagramPacket(data, data.size, p.target, PORT))
                        } catch (e: Exception) {
                            err[p.key] = e.message ?: e.javaClass.simpleName
                        }
                    }
                    if (nextRound < 2) {
                        for ((host, bc) in gameTargets) {
                            val sock = socks[host] ?: continue
                            val target = try {
                                InetAddress.getByName(host)
                            } catch (_: Exception) {
                                continue
                            }
                            for (port in GAME_PORTS) {
                                for (q in listOf(A2S_INFO, XASH_INFO)) {
                                    try {
                                        sock.send(DatagramPacket(q, q.size, target, port))
                                    } catch (_: Exception) {
                                    }
                                }
                            }
                        }
                    }
                    nextRound++
                }
                var got = false
                while (true) {
                    val rx = replies.poll() ?: break
                    val pkt = rx.pkt
                    val at = rx.at
                    got = true
                    if (isSelf(layout, pkt.address.hostAddress)) continue
                    if (pkt.length >= 5 && pkt.data[0] == (-1).toByte()) {
                        val text = describeGameReply(pkt.data.copyOf(pkt.length))
                        if (text != null) {
                            val bc = gameTargets.any { it.first == rx.via && it.second }
                            val from = pkt.address.hostAddress ?: "?"
                            if (gameAnswers.none { it.from == from && it.port == pkt.port && it.viaBroadcast == bc && it.text == text }) {
                                gameAnswers.add(GameAnswer(from, pkt.port, bc, text))
                            }
                        }
                        continue
                    }
                    val parts = String(pkt.data, 0, pkt.length, Charsets.UTF_8).split(' ', limit = 6)
                    if (parts.size >= 5 && parts[0] == "LBR1" && parts[1] == id) {
                        val key = parts[2]
                        val probe = probes.firstOrNull { it.key == key }
                        val from = pkt.address.hostAddress
                        if (parts[4] != "ok") {
                            err[key] = "данные искажены"
                        } else if (probe != null && probe.unicast && pkt.address != probe.target) {
                            // A program with a connected socket or a check of the sender address would drop this reply.
                            err[key] = "ответ пришёл с адреса $from, а не с ${probe.host}"
                        } else if (!ok.containsKey(key)) {
                            ok[key] = at - (sentAt["$key#${parts[3]}"] ?: t0)
                        }
                    }
                }
                if (!got) {
                    try {
                        Thread.sleep(5)
                    } catch (_: InterruptedException) {
                    }
                }
            }
        } catch (e: Exception) {
            return "Проверка не выполнена: ${e.message}"
        } finally {
            for (sock in socks.values) {
                try {
                    sock.close()
                } catch (_: Exception) {
                }
            }
        }
        val sb = StringBuilder("Проверка LAN")
        for (p in probes) {
            sb.append('\n').append(p.label).append(" — ")
            val t = ok[p.key]
            if (t != null && !err.containsKey(p.key)) {
                sb.append("OK, ").append(t).append(" мс")
            } else {
                sb.append("нет ответа")
                val e = err[p.key]
                if (e != null) sb.append(" (").append(e).append(')')
            }
        }
        sb.append("\nTCP 256 КБ → ${layout.peer} — ").append(tcpProbe(layout.peer))
        if (real != null) sb.append("\nTCP 256 КБ → $real — ").append(tcpProbe(real))
        if (layout.peer6.isNotEmpty()) {
            sb.append("\nIPv6 TCP 256 КБ → ${layout.peer6} — ").append(tcpProbe(layout.peer6))
            if (real6 != null) sb.append("\nIPv6 TCP 256 КБ → $real6 — ").append(tcpProbe(real6))
        }
        sb.append("\n").append(gameReport(layout, gameAnswers))
        val extra = try {
            extraReport?.invoke()
        } catch (_: Exception) {
            null
        }
        if (!extra.isNullOrBlank()) sb.append('\n').append(extra)
        if (ok.isEmpty()) sb.append("\nУбедитесь, что у другого участника тоже открыто соединение (статус «Подключено»).")
        return sb.toString()
    }
}
