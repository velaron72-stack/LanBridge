package app.lanbridge.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.NetworkInterface

object NetInfo {
    /**
     * IPv4 addresses that a mirrored route of the friend's real address must never take over: this device's own
     * addresses, and the gateways and DNS servers of its real networks.
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
                for (la in lp.linkAddresses) {
                    val a = la.address
                    if (a is Inet4Address) a.hostAddress?.let { out.add(it) }
                }
                for (d in lp.dnsServers) {
                    if (d is Inet4Address) d.hostAddress?.let { out.add(it) }
                }
                for (r in lp.routes) {
                    val g = r.gateway
                    if (g is Inet4Address) g.hostAddress?.let { out.add(it) }
                }
            }
        } catch (_: Exception) {
        }
        return out
    }


    /** Local IPv4 addresses of the real networks (the tunnel's own interface is skipped), Wi-Fi first. */
    fun localIpv4(context: Context): List<String> {
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
                    if (a is Inet4Address && !a.isLoopbackAddress && !a.isLinkLocalAddress && !a.isAnyLocalAddress) {
                        a.hostAddress?.let { out.add(it) }
                    }
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
                        if (a is Inet4Address && !a.isLoopbackAddress && !a.isLinkLocalAddress) a.hostAddress?.let { out.add(it) }
                    }
                }
            } catch (_: Exception) {
            }
        }
        return out.toList()
    }
}
