package app.lanbridge.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface

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

    /**
     * Addresses (IPv4 and IPv6, in [canon] form) that a mirrored route of the friend's real address must never take
     * over: this device's own addresses, and the gateways and DNS servers of its real networks.
     */
    fun sensitiveAddresses(context: Context): Set<String> {
        val out = HashSet<String>()
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            @Suppress("DEPRECATION")
            val nets = cm.allNetworks.toList()
            for (n in nets) {
                val caps = cm.getNetworkCapabilities(n) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                val lp = cm.getLinkProperties(n) ?: continue
                for (la in lp.linkAddresses) la.address.hostAddress?.let { out.add(canon(it)) }
                for (d in lp.dnsServers) d.hostAddress?.let { out.add(canon(it)) }
                for (r in lp.routes) r.gateway?.hostAddress?.let { out.add(canon(it)) }
            }
        } catch (_: Exception) {
        }
        return out
    }

    private fun usable4(a: InetAddress) =
        a is Inet4Address && !a.isLoopbackAddress && !a.isLinkLocalAddress && !a.isAnyLocalAddress

    /** Global and unique-local IPv6 addresses only: link-local ones are useless to a friend, site-local are obsolete. */
    private fun usable6(a: InetAddress) =
        a is Inet6Address && !a.isLoopbackAddress && !a.isLinkLocalAddress && !a.isAnyLocalAddress &&
            !a.isMulticastAddress && !a.isSiteLocalAddress

    private fun collect(context: Context, accept: (InetAddress) -> Boolean): List<String> {
        val out = LinkedHashSet<String>()
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            @Suppress("DEPRECATION")
            val nets = cm.allNetworks.toList()
            val ordered = nets.sortedBy { n ->
                val c = cm.getNetworkCapabilities(n)
                if (c != null && c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) 0 else 1
            }
            for (n in ordered) {
                val caps = cm.getNetworkCapabilities(n) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                val lp = cm.getLinkProperties(n) ?: continue
                for (la in lp.linkAddresses) {
                    val a = la.address
                    if (accept(a)) a.hostAddress?.let { out.add(canon(it)) }
                }
            }
        } catch (_: Exception) {
        }
        if (out.isEmpty()) {
            try {
                val ifs = NetworkInterface.getNetworkInterfaces()
                while (ifs != null && ifs.hasMoreElements()) {
                    val ni = ifs.nextElement()
                    if (!ni.isUp || ni.isLoopback) continue
                    val nm = ni.name ?: ""
                    if (nm.startsWith("tun") || nm.startsWith("dummy")) continue
                    val addrs = ni.inetAddresses
                    while (addrs.hasMoreElements()) {
                        val a = addrs.nextElement()
                        if (accept(a)) a.hostAddress?.let { out.add(canon(it)) }
                    }
                }
            } catch (_: Exception) {
            }
        }
        return out.toList()
    }

    /** Local IPv4 addresses of the real networks (the tunnel's own interface is skipped), Wi-Fi first. */
    fun localIpv4(context: Context): List<String> = collect(context) { usable4(it) }

    /** Local global/unique-local IPv6 addresses of the real networks, Wi-Fi first. */
    fun localIpv6(context: Context): List<String> = collect(context) { usable6(it) }

    /** Everything the connection code carries: IPv4 first (the tunnel's transport), then IPv6. */
    fun localAddresses(context: Context): List<String> = localIpv4(context) + localIpv6(context)
}
