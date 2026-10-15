package app.lanbridge.vpn

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import app.lanbridge.App
import app.lanbridge.MainActivity
import app.lanbridge.R
import app.lanbridge.core.Native
import app.lanbridge.core.NetLayout
import app.lanbridge.core.Phase
import app.lanbridge.core.Prefs
import app.lanbridge.core.TunnelController
import app.lanbridge.core.UiState
import app.lanbridge.ui.Fmt
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the TUN interface of the virtual LAN. Only the virtual subnets (IPv4 and IPv6 at the same time), multicast and
 * limited broadcast are routed into the tunnel, so ordinary Internet traffic of the phone is untouched. Packet work
 * happens in the native engine.
 */
class TunnelVpnService : VpnService() {
    companion object {
        const val ACTION_START = "app.lanbridge.action.START"
        const val ACTION_STOP = "app.lanbridge.action.STOP"
        private const val NOTIF_ID = 17
    }

    private val started = AtomicBoolean(false)
    private val stopping = AtomicBoolean(false)

    @Volatile
    private var watcher: Thread? = null
    /** Version of the network layout the current TUN was built from; a group changes it when somebody comes or goes. */
    @Volatile
    private var appliedVer = 0L
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (intent.action == ACTION_STOP) {
            Thread({ shutdown() }, "lanbridge-stop").start()
            return START_NOT_STICKY
        }
        startForegroundCompat(buildNotification("Подключение…"))
        if (started.compareAndSet(false, true)) {
            stopping.set(false)
            Thread({ runTunnel() }, "lanbridge-start").start()
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        Native.note("VPN отозван системой")
        Thread({ shutdown() }, "lanbridge-revoke").start()
    }

    override fun onDestroy() {
        if (!stopping.get()) {
            try {
                Native.stop()
            } catch (_: Throwable) {
            }
            releaseLocks()
            TunnelController.onTunnelStopped()
        }
        started.set(false)
        super.onDestroy()
    }

    /**
     * Builds the TUN interface. With [withReal] the device's real address becomes the primary address of the tunnel
     * and the friend's real addresses are routed into it, so programs that bind to or advertise real addresses keep
     * working; the virtual /24 stays available next to them. With [withV6] the IPv6 side is added as well: the
     * virtual unique-local /64, link-local multicast (ff00::/8) and, with [withReal], the mirrored real IPv6 addresses.
     */
    private fun establishTun(layout: NetLayout, mtu: Int, withReal: Boolean, withV6: Boolean): ParcelFileDescriptor? {
        val b = Builder().setSession("LanBridge").setMtu(mtu)
        if (withReal) {
            val primary = layout.realMine.firstOrNull()
            if (primary != null) b.addAddress(primary, 32)
        }
        b.addAddress(layout.my, layout.prefix)
        if (withV6) {
            if (withReal) {
                val primary6 = layout.realMine6.firstOrNull()
                if (primary6 != null) b.addAddress(primary6, 128)
            }
            b.addAddress(layout.my6, layout.prefix6)
        }
        b.addRoute(layout.net, layout.prefix)
        b.addRoute("224.0.0.0", 4)
        b.addRoute("255.255.255.255", 32)
        if (withV6) {
            b.addRoute(layout.net6, layout.prefix6)
            b.addRoute("ff00::", 8)
        }
        if (withReal) {
            for (a in layout.aliasRoutes) b.addRoute(a, 32)
            if (withV6) for (a in layout.aliasRoutes6) b.addRoute(a, 128)
        }
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
        return b.establish()
    }

    /** The TUN together with the tier of addresses the system accepted. */
    private class Built(val pfd: ParcelFileDescriptor, val real: Boolean, val v6: Boolean)

    /**
     * From the fullest set of addresses down to the plain IPv4 virtual network: the first tier the system accepts.
     * Returns null when the system hands out no interface at all.
     */
    private fun buildTun(layout: NetLayout, mtu: Int): Built? {
        val wantReal = layout.realMine.isNotEmpty() || layout.aliasRoutes.isNotEmpty() ||
            layout.realMine6.isNotEmpty() || layout.aliasRoutes6.isNotEmpty()
        val want6 = layout.my6.isNotEmpty()
        val tiers = ArrayList<Pair<Boolean, Boolean>>()
        if (wantReal) tiers += true to want6
        if (want6) tiers += false to true
        tiers += false to false
        for ((real, v6) in tiers.distinct()) {
            var pfd: ParcelFileDescriptor? = null
            try {
                pfd = establishTun(layout, mtu, real, v6)
            } catch (t: Throwable) {
                Native.note("TUN (реальные адреса: $real, IPv6: $v6) не создан: ${t.message}")
            }
            if (pfd != null) return Built(pfd, real, v6)
        }
        return null
    }

    private fun describeTun(layout: NetLayout, b: Built, fd: Int, mtu: Int): String =
        "TUN создан: fd=$fd, ${layout.my}/${layout.prefix}, MTU $mtu, " +
            (if (b.real) "реальные адреса: основной ${layout.realMine.firstOrNull() ?: "-"}, маршруты ${layout.aliasRoutes.joinToString()}" else "только виртуальная сеть") +
            (if (b.v6) "; IPv6: ${layout.my6}/${layout.prefix6}" +
                (if (b.real) ", реальные: основной ${layout.realMine6.firstOrNull() ?: "-"}, маршруты ${layout.aliasRoutes6.joinToString()}" else "")
            else "; IPv6 не включён") +
            (if (layout.group) "; группа, слот ${layout.slot}, версия сети ${layout.ver}" else "")

    private fun runTunnel() {
        try {
            val layout = TunnelController.layout ?: throw IllegalStateException("нет данных о сети")
            val prefs = Prefs(this)
            val mtu = prefs.mtu
            val built = buildTun(layout, mtu) ?: throw IllegalStateException("система не выдала VPN-интерфейс (разрешение отозвано?)")
            val fd = built.pfd.detachFd()
            Native.note(describeTun(layout, built, fd, mtu))
            // The tunnel's own UDP sockets (IPv4 and IPv6) must bypass the VPN, or the tunnel would carry itself.
            for ((family, sfd) in listOf("IPv4" to Native.socketFd(), "IPv6" to Native.socketFd6())) {
                if (sfd < 0) continue
                try {
                    if (!protect(sfd)) Native.note("protect() сокета $family (fd=$sfd) вернул false")
                } catch (t: Throwable) {
                    Native.note("protect() сокета $family: ${t.message}")
                }
            }
            appliedVer = layout.ver
            val rc = Native.start(fd, mtu)
            if (rc != 0) {
                throw IllegalStateException(Native.text(Native.lastError()).ifBlank { "код ошибки $rc" })
            }
            if (stopping.get()) {
                Native.stop()
                return
            }
            acquireLocks(prefs.keepAwake)
            startWatcher()
        } catch (t: Throwable) {
            Native.note("запуск туннеля: ${t.message}")
            TunnelController.onTunnelError(t.message ?: t.javaClass.simpleName)
            shutdown()
        }
    }

    /**
     * A group changed its membership: the addresses of the network are different now, so the TUN is built again
     * from the new layout and handed to the core, which keeps the sessions with the other devices.
     * Returns true when the new TUN is in place.
     */
    private fun relayout(layout: NetLayout): Boolean {
        val mtu = Prefs(this).mtu
        val built = buildTun(layout, mtu)
        if (built == null) {
            Native.note("пересборка TUN: система не выдала интерфейс, остаётся прежний")
            return false
        }
        val fd = built.pfd.detachFd()
        val rc = Native.swapTun(fd)
        if (rc != 0) {
            Native.note("пересборка TUN: ядро не приняло интерфейс (код $rc)")
            return false
        }
        Native.note(describeTun(layout, built, fd, mtu).replace("TUN создан", "TUN пересобран"))
        appliedVer = layout.ver
        return true
    }

    private fun shutdown() {
        if (!stopping.compareAndSet(false, true)) return
        watcher?.interrupt()
        try {
            Native.stop()
        } catch (_: Throwable) {
        }
        releaseLocks()
        TunnelController.onTunnelStopped()
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) {
        }
        stopSelf()
    }

    // ------------------------------------------------------------------ notification

    private fun startForegroundCompat(n: Notification) {
        try {
            ServiceCompat.startForeground(this, NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        } catch (e: Exception) {
            Native.note("startForeground: ${e.message}")
            try {
                startForeground(NOTIF_ID, n)
            } catch (_: Exception) {
            }
        }
    }

    private fun buildNotification(text: String): Notification {
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), flags,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, TunnelVpnService::class.java).setAction(ACTION_STOP), flags,
        )
        return NotificationCompat.Builder(this, App.CHANNEL_TUNNEL)
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            .setContentTitle("LanBridge")
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(open)
            .addAction(0, "Отключить", stop)
            .build()
    }

    private fun describe(ui: UiState): String {
        if (ui.groupRole != 0) {
            val up = ui.members.filter { it.state == 2 }
            return when (ui.phase) {
                Phase.CONNECTING ->
                    if (ui.groupRole == 1 && ui.membersKnown == 0) "Группа открыта: ждём участников" else "Группа: соединяюсь…"
                Phase.CONNECTED -> {
                    val names = up.take(3).joinToString(", ") { Fmt.memberName(it) } + (if (up.size > 3) " и ещё ${up.size - 3}" else "")
                    "Группа: $names" + (ui.layout?.let { " · ${it.my}" } ?: "")
                }
                Phase.STALLED -> "Группа: нет связи с участниками"
                Phase.FAILED -> "Не удалось подключиться"
                else -> "Подключение…"
            }
        }
        val name = ui.members.firstOrNull()?.name?.ifBlank { null } ?: ui.friend?.name?.ifBlank { null } ?: "друг"
        return when (ui.phase) {
            Phase.CONNECTING -> "Соединяюсь: $name…"
            Phase.CONNECTED -> {
                val rtt = ui.stats?.rttMs ?: -1L
                "Подключено: $name" + (if (rtt >= 0) " · $rtt мс" else "") + (ui.layout?.let { " · ${it.my}" } ?: "")
            }
            Phase.STALLED -> if (ui.stats?.peerLeft == true) "Друг отключился" else "Нет ответа от друга"
            Phase.FAILED -> "Не удалось подключиться"
            else -> "Подключение…"
        }
    }

    /**
     * Every half second: the notification text, and the layout of the network. A change of the layout is applied
     * after 1.5 s of quiet, so several devices that join one after another cost a single rebuild of the TUN.
     */
    private fun startWatcher() {
        val t = Thread({
            val nm = getSystemService(NotificationManager::class.java)
            var last = ""
            var lastNotifyAt = 0L
            var seenVer = appliedVer
            var seenSince = 0L
            var retryAt = 0L
            try {
                while (!stopping.get()) {
                    val now = System.currentTimeMillis()
                    if (now - lastNotifyAt >= 2000L) {
                        lastNotifyAt = now
                        val text = describe(TunnelController.ui.value)
                        if (text != last) {
                            last = text
                            nm.notify(NOTIF_ID, buildNotification(text))
                        }
                    }
                    val l = TunnelController.layout
                    if (l != null && l.group && l.ver != appliedVer) {
                        if (l.ver != seenVer) {
                            seenVer = l.ver
                            seenSince = now
                        }
                        if (now - seenSince >= 1500L && now >= retryAt) {
                            if (!relayout(l)) retryAt = now + 10000L
                        }
                    }
                    Thread.sleep(500)
                }
            } catch (_: InterruptedException) {
            } catch (_: Exception) {
            }
        }, "lanbridge-notify")
        t.isDaemon = true
        watcher = t
        t.start()
    }

    // ------------------------------------------------------------------ keep the device awake while tunnelling

    private fun acquireLocks(keepAwake: Boolean) {
        if (!keepAwake) return
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            val wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "LanBridge:tunnel")
            wl.setReferenceCounted(false)
            wl.acquire(12L * 60L * 60L * 1000L)
            wakeLock = wl
        } catch (_: Exception) {
        }
        try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val wfl = wm.createWifiLock(wifiLockMode(), "LanBridge:wifi")
            wfl.setReferenceCounted(false)
            wfl.acquire()
            wifiLock = wfl
        } catch (_: Exception) {
        }
    }

    @Suppress("DEPRECATION")
    private fun wifiLockMode(): Int =
        if (Build.VERSION.SDK_INT >= 29) WifiManager.WIFI_MODE_FULL_LOW_LATENCY else WifiManager.WIFI_MODE_FULL_HIGH_PERF

    private fun releaseLocks() {
        try {
            wakeLock?.let { if (it.isHeld) it.release() }
        } catch (_: Exception) {
        }
        try {
            wifiLock?.let { if (it.isHeld) it.release() }
        } catch (_: Exception) {
        }
        wakeLock = null
        wifiLock = null
    }
}
