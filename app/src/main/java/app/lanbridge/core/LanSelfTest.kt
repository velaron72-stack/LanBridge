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
import java.net.SocketTimeoutException
import java.util.Locale
import java.util.zip.CRC32

/**
 * Real-socket check of the virtual LAN. While the tunnel is up every device answers probes on port 41377
 * (UDP and TCP). "Проверка LAN" sends them to the friend and reports what came back: unicast to the virtual and to the
 * mirrored real address, limited and directed broadcast, multicast, a UDP datagram that needs IP fragmentation and a
 * TCP transfer. The result shows which kinds of traffic really cross the tunnel.
 */
object LanSelfTest {
    const val PORT = 41377
    private const val MCAST = "239.255.77.77"
    private const val BIG = 4000
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

    private fun isSelf(layout: NetLayout, addr: String?): Boolean =
        addr != null && (addr == layout.my || layout.realMine.contains(addr))

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

    private class Probe(val key: String, val label: String, val host: String, val body: Int, val unicast: Boolean = false)

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

    /** Blocking, up to about ten seconds. Call from a background thread. */
    fun run(layout: NetLayout): String {
        val probes = ArrayList<Probe>()
        probes += Probe("u", "Unicast ${layout.peer}", layout.peer, 0, true)
        val real = layout.aliasRoutes.firstOrNull()
        if (real != null) probes += Probe("r", "Unicast $real (реальный адрес друга)", real, 0, true)
        probes += Probe("b1", "Broadcast 255.255.255.255", "255.255.255.255", 0)
        probes += Probe("b2", "Broadcast ${layout.bcast}", layout.bcast, 0)
        probes += Probe("m", "Multicast $MCAST", MCAST, 0)
        probes += Probe("f", "UDP $BIG Б (фрагментация IP)", layout.peer, BIG, true)

        val ok = LinkedHashMap<String, Long>()
        val err = HashMap<String, String>()
        var s: MulticastSocket? = null
        try {
            val sock = MulticastSocket()
            s = sock
            sock.broadcast = true
            sock.soTimeout = 40
            val ni = findIface(layout.my)
            if (ni != null) {
                try {
                    sock.networkInterface = ni
                } catch (_: Exception) {
                }
            }
            val id = (SystemClock.elapsedRealtime() % 100000L).toString()
            val sentAt = HashMap<String, Long>()
            val rounds = longArrayOf(0L, 250L, 600L)
            var nextRound = 0
            val t0 = SystemClock.elapsedRealtime()
            val buf = ByteArray(2000)
            while (true) {
                val now = SystemClock.elapsedRealtime()
                if (now - t0 > 3000L || ok.size >= probes.size) break
                if (nextRound < rounds.size && now - t0 >= rounds[nextRound]) {
                    for (p in probes) {
                        if (ok.containsKey(p.key)) continue
                        val body = bodyOf(p.body)
                        val head = "LBT1 $id ${p.key} $nextRound ${crcOf(body)} ${body.size}\n".toByteArray(Charsets.UTF_8)
                        val data = head + body
                        sentAt["${p.key}#$nextRound"] = SystemClock.elapsedRealtime()
                        try {
                            sock.send(DatagramPacket(data, data.size, InetAddress.getByName(p.host), PORT))
                        } catch (e: Exception) {
                            err[p.key] = e.message ?: e.javaClass.simpleName
                        }
                    }
                    nextRound++
                }
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    sock.receive(pkt)
                    val at = SystemClock.elapsedRealtime()
                    if (isSelf(layout, pkt.address.hostAddress)) continue
                    val parts = String(pkt.data, 0, pkt.length, Charsets.UTF_8).split(' ', limit = 6)
                    if (parts.size >= 5 && parts[0] == "LBR1" && parts[1] == id) {
                        val key = parts[2]
                        val probe = probes.firstOrNull { it.key == key }
                        val from = pkt.address.hostAddress
                        if (parts[4] != "ok") {
                            err[key] = "данные искажены"
                        } else if (probe != null && probe.unicast && from != probe.host) {
                            // A program with a connected socket or a check of the sender address would drop this reply.
                            err[key] = "ответ пришёл с адреса $from, а не с ${probe.host}"
                        } else if (!ok.containsKey(key)) {
                            ok[key] = at - (sentAt["$key#${parts[3]}"] ?: t0)
                        }
                    }
                } catch (_: SocketTimeoutException) {
                }
            }
        } catch (e: Exception) {
            return "Проверка не выполнена: ${e.message}"
        } finally {
            try {
                s?.close()
            } catch (_: Exception) {
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
        if (ok.isEmpty()) sb.append("\nУбедитесь, что у друга тоже открыто соединение (статус «Подключено»).")
        return sb.toString()
    }
}
