package app.lanbridge.core

import android.content.Context
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface

/** The addresses of this PC's real networks: what goes into the connection code as candidates. */
object NetInfo {
    private val IPV4_LITERAL = Regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")

    /**
     * One text form for an IP literal: "2001:db8::1" and "2001:db8:0:0:0:0:0:1" give the same string, a zone suffix
     * is dropped. Anything that is not a literal is returned unchanged (no name lookup ever happens here).
     */
    fun canon(s: String): String = try {
        val t = s.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
        if (t.contains(':') || IPV4_LITERAL.matches(t)) InetAddress.getByName(t).hostAddress?.substringBefore('%') ?: s else s
    } catch (_: Exception) {
        s
    }

    /** Adapters whose addresses are of no use to a friend: our own, other virtual ones, loopback, Bluetooth. */
    private val SKIP_WORDS = listOf(
        "lanbridge", "wintun", "vmware", "virtualbox", "vbox", "hyper-v", "vethernet", "wsl", "loopback", "bluetooth",
        "teredo", "isatap", "6to4", "pseudo", "npcap", "docker", "tap-windows", "wan miniport",
    )

    private fun skipped(ni: NetworkInterface): Boolean {
        val text = ((ni.displayName ?: "") + " " + (ni.name ?: "")).lowercase()
        return SKIP_WORDS.any { text.contains(it) }
    }

    private fun usable4(a: InetAddress) =
        a is Inet4Address && !a.isLoopbackAddress && !a.isLinkLocalAddress && !a.isAnyLocalAddress

    /** Global and unique-local IPv6 addresses only: link-local ones are useless to a friend, site-local are obsolete. */
    private fun usable6(a: InetAddress) =
        a is Inet6Address && !a.isLoopbackAddress && !a.isLinkLocalAddress && !a.isAnyLocalAddress &&
            !a.isMulticastAddress && !a.isSiteLocalAddress

    private fun interfaces(): List<NetworkInterface> {
        val out = ArrayList<NetworkInterface>()
        try {
            val e = NetworkInterface.getNetworkInterfaces()
            while (e != null && e.hasMoreElements()) {
                val ni = e.nextElement()
                try {
                    if (ni.isUp && !ni.isLoopback) out.add(ni)
                } catch (_: Exception) {
                }
            }
        } catch (_: Exception) {
        }
        return out
    }

    private fun collect(accept: (InetAddress) -> Boolean): List<String> {
        val out = LinkedHashSet<String>()
        for (ni in interfaces()) {
            if (skipped(ni)) continue
            val addrs = ni.inetAddresses
            while (addrs.hasMoreElements()) {
                val a = addrs.nextElement()
                if (accept(a)) a.hostAddress?.let { out.add(canon(it)) }
            }
        }
        return out.toList()
    }

    /** Addresses that a mirrored route must never take over: this PC's own addresses on all its adapters. */
    @Suppress("UNUSED_PARAMETER")
    fun sensitiveAddresses(context: Context): Set<String> {
        val out = HashSet<String>()
        for (ni in interfaces()) {
            val addrs = ni.inetAddresses
            while (addrs.hasMoreElements()) addrs.nextElement().hostAddress?.let { out.add(canon(it)) }
        }
        return out
    }

    @Suppress("UNUSED_PARAMETER")
    fun localIpv4(context: Context): List<String> = collect { usable4(it) }

    @Suppress("UNUSED_PARAMETER")
    fun localIpv6(context: Context): List<String> = collect { usable6(it) }

    /** Everything the connection code carries: IPv4 first (the tunnel's transport), then IPv6. */
    fun localAddresses(context: Context): List<String> = localIpv4(context) + localIpv6(context)
}
