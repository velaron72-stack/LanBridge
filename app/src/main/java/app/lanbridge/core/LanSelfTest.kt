package app.lanbridge.core

import android.os.SystemClock
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException

/**
 * Real-socket check of the virtual LAN. While the tunnel is up every device answers small probes on UDP 41377
 * (unicast, limited broadcast, directed broadcast, multicast). "Проверка LAN" sends them to the friend and reports
 * which kinds came back, so it is visible whether broadcast/multicast really cross the tunnel.
 */
object LanSelfTest {
    const val PORT = 41377
    private const val MCAST = "239.255.77.77"

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

    private class Responder(val layout: NetLayout, val devName: String) : Thread("lanbridge-responder") {
        @Volatile
        private var closed = false

        @Volatile
        private var sock: MulticastSocket? = null

        init {
            isDaemon = true
        }

        fun shutdown() {
            closed = true
            try {
                sock?.close()
            } catch (_: Exception) {
            }
        }

        override fun run() {
            try {
                val s = MulticastSocket(PORT)
                sock = s
                s.broadcast = true
                try {
                    val group = InetAddress.getByName(MCAST)
                    val ni = findIface(layout.my)
                    if (ni != null) s.joinGroup(InetSocketAddress(group, 0), ni) else s.joinGroup(group)
                } catch (e: Exception) {
                    Native.note("проверка: не удалось войти в multicast-группу: ${e.message}")
                }
                val buf = ByteArray(512)
                while (!closed) {
                    val p = DatagramPacket(buf, buf.size)
                    s.receive(p)
                    val msg = String(p.data, 0, p.length, Charsets.UTF_8)
                    if (!msg.startsWith("LBT1 ")) continue
                    if (p.address.hostAddress == layout.my) continue
                    val reply = ("LBR1 " + msg.substring(5) + " " + devName).toByteArray(Charsets.UTF_8)
                    s.send(DatagramPacket(reply, reply.size, p.address, p.port))
                }
            } catch (e: Exception) {
                if (!closed) Native.note("проверка: ответчик остановлен: ${e.message}")
            }
        }
    }

    /** Blocking, about three seconds. Call from a background thread. */
    fun run(layout: NetLayout): String {
        val probes = listOf(
            Triple("u", "Unicast ${layout.peer}", layout.peer),
            Triple("b1", "Broadcast 255.255.255.255", "255.255.255.255"),
            Triple("b2", "Broadcast ${layout.bcast}", layout.bcast),
            Triple("m", "Multicast $MCAST", MCAST),
        )
        val ok = LinkedHashMap<String, Long>()
        val err = HashMap<String, String>()
        var s: MulticastSocket? = null
        try {
            val sock = MulticastSocket()
            s = sock
            sock.broadcast = true
            sock.soTimeout = 250
            val ni = findIface(layout.my)
            if (ni != null) {
                try {
                    sock.networkInterface = ni
                } catch (_: Exception) {
                }
            }
            val id = (SystemClock.elapsedRealtime() % 100000L).toString()
            val sent = HashMap<String, Long>()
            for (round in 0 until 2) {
                for (p in probes) {
                    val data = "LBT1 $id ${p.first}".toByteArray(Charsets.UTF_8)
                    try {
                        if (!sent.containsKey(p.first)) sent[p.first] = SystemClock.elapsedRealtime()
                        sock.send(DatagramPacket(data, data.size, InetAddress.getByName(p.third), PORT))
                    } catch (e: Exception) {
                        err[p.first] = e.message ?: e.javaClass.simpleName
                    }
                }
                if (round == 0) Thread.sleep(150)
            }
            val buf = ByteArray(512)
            val deadline = SystemClock.elapsedRealtime() + 2500L
            while (SystemClock.elapsedRealtime() < deadline && ok.size < probes.size) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    sock.receive(pkt)
                    if (pkt.address.hostAddress == layout.my) continue
                    val parts = String(pkt.data, 0, pkt.length, Charsets.UTF_8).split(' ')
                    if (parts.size >= 3 && parts[0] == "LBR1" && parts[1] == id) {
                        val k = parts[2]
                        if (!ok.containsKey(k)) ok[k] = SystemClock.elapsedRealtime() - (sent[k] ?: deadline)
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
            sb.append('\n').append(p.second).append(" — ")
            val t = ok[p.first]
            if (t != null) {
                sb.append("OK, ").append(t).append(" мс")
            } else {
                sb.append("нет ответа")
                val e = err[p.first]
                if (e != null) sb.append(" (").append(e).append(')')
            }
        }
        if (ok.isEmpty()) sb.append("\nУбедитесь, что у друга тоже открыто соединение (статус «Подключено»).")
        return sb.toString()
    }
}
