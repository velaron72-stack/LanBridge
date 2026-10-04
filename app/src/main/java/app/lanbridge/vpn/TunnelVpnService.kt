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
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import app.lanbridge.App
import app.lanbridge.MainActivity
import app.lanbridge.R
import app.lanbridge.core.Native
import app.lanbridge.core.Phase
import app.lanbridge.core.Prefs
import app.lanbridge.core.TunnelController
import app.lanbridge.core.UiState
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the TUN interface of the virtual LAN. Only the virtual subnet, multicast and limited broadcast are routed into
 * the tunnel, so ordinary Internet traffic of the phone is untouched. Packet work happens in the native engine.
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

    private fun runTunnel() {
        try {
            val layout = TunnelController.layout ?: throw IllegalStateException("нет данных о сети")
            val prefs = Prefs(this)
            val mtu = prefs.mtu
            val b = Builder()
                .setSession("LanBridge")
                .setMtu(mtu)
                .addAddress(layout.my, layout.prefix)
                .addRoute(layout.net, layout.prefix)
                .addRoute("224.0.0.0", 4)
                .addRoute("255.255.255.255", 32)
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
            val pfd = b.establish() ?: throw IllegalStateException("система не выдала VPN-интерфейс (разрешение отозвано?)")
            val fd = pfd.detachFd()
            Native.note("TUN создан: fd=$fd, ${layout.my}/${layout.prefix}, MTU $mtu")
            try {
                protect(Native.socketFd())
            } catch (_: Throwable) {
            }
            val rc = Native.start(fd, TunnelController.pendingPassword.toByteArray(Charsets.UTF_8), mtu)
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
        val name = ui.friend?.name?.ifBlank { null } ?: "друг"
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

    private fun startWatcher() {
        val t = Thread({
            val nm = getSystemService(NotificationManager::class.java)
            var last = ""
            try {
                while (!stopping.get()) {
                    val text = describe(TunnelController.ui.value)
                    if (text != last) {
                        last = text
                        nm.notify(NOTIF_ID, buildNotification(text))
                    }
                    Thread.sleep(2000)
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
