package app.lanbridge.vpn

import android.content.Context
import android.content.Intent
import app.lanbridge.core.FirewallGuard
import app.lanbridge.core.Native
import app.lanbridge.core.NetLayout
import app.lanbridge.core.Phase
import app.lanbridge.core.Prefs
import app.lanbridge.core.TunnelController
import app.lanbridge.core.UiState
import app.lanbridge.core.WinTun
import app.lanbridge.ui.Fmt
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The PC counterpart of the Android VpnService: owns the Wintun adapter of the virtual LAN. The adapter carries the
 * virtual IPv4 and IPv6 subnets of the group (on-link routes come with the addresses; multicast and limited
 * broadcast prefer the adapter because its interface metric is 1), ordinary Internet traffic of the PC is untouched.
 * Packet work happens in the native core, which talks to the adapter through a socket pair that wintun_win.cpp pumps.
 *
 * Not mirrored on the PC (the phone does it): real addresses of the other devices. Other participants are reached
 * by their virtual addresses.
 */
class TunnelVpnService {
    companion object {
        const val ACTION_START = "app.lanbridge.action.START"
        const val ACTION_STOP = "app.lanbridge.action.STOP"

        private val impl = Impl()

        /** The commands of the screens: start the tunnel, stop it. */
        fun dispatch(intent: Intent) {
            when (intent.action) {
                ACTION_START -> impl.start()
                ACTION_STOP -> impl.stopAsync()
            }
        }

        /** True from the moment the tunnel is asked to start until it is fully stopped. */
        val isRunning: Boolean get() = impl.isRunning

        /** Closes the tunnel and removes the adapter; returns when it is done. For the window's close button. */
        fun shutdownBlocking() = impl.shutdown()

        /** The one-line state of the tunnel, for the window title. */
        fun statusText(ui: UiState): String = impl.describe(ui)

        /**
         * The user's choice about Windows Firewall has changed (the question at the start, the settings): applied at once
         * when the tunnel is open, otherwise at its next start. Choosing "keep" also puts back what an earlier run switched off.
         */
        fun applyFirewallChoice() = impl.applyFirewallChoice()

        /** At the start of the app: puts the firewall back if an earlier run ended without doing it. */
        fun recoverFirewall() = impl.recoverFirewall()
    }

    private class Impl {
        private val started = AtomicBoolean(false)
        private val stopping = AtomicBoolean(false)

        @Volatile
        private var watcher: Thread? = null

        /** Version of the network layout the adapter was set up from; a group changes it when somebody comes or goes. */
        @Volatile
        private var appliedVer = 0L

        @Volatile
        private var netSetupGen = 0

        /** Serialises the changes of the firewall state: the choice of the user and the end of the tunnel. */
        private val firewallLock = Any()

        val isRunning: Boolean get() = started.get()

        fun start() {
            if (started.compareAndSet(false, true)) {
                stopping.set(false)
                val t = Thread({ runTunnel() }, "lanbridge-start")
                t.isDaemon = true
                t.start()
            }
        }

        fun stopAsync() {
            val t = Thread({ shutdown() }, "lanbridge-stop")
            t.isDaemon = true
            t.start()
        }

        private fun runTunnel() {
            try {
                val layout = TunnelController.layout ?: throw IllegalStateException("нет данных о сети")
                val prefs = Prefs(Context())
                val mtu = prefs.mtu
                if (!WinTun.isElevated()) {
                    throw IllegalStateException("нужны права администратора: закройте LanBridge и запустите заново, подтвердив запрос UAC")
                }
                WinTun.loadDriverLibrary()?.let { throw IllegalStateException(it) }
                val fd = WinTun.open(WinTun.ADAPTER_NAME, WinTun.ADAPTER_GUID)
                if (fd < 0) throw IllegalStateException(WinTun.error().ifBlank { "адаптер Wintun не создан" })
                try {
                    applyAddresses(layout, mtu)
                } catch (t: Throwable) {
                    // the engine does not own the descriptor yet
                    WinTun.close()
                    throw t
                }
                Native.note(describeTun(layout, fd, mtu))
                appliedVer = layout.ver
                val rc = Native.start(fd, mtu)
                if (rc != 0) {
                    WinTun.close()
                    throw IllegalStateException(Native.text(Native.lastError()).ifBlank { "код ошибки $rc" })
                }
                if (stopping.get()) {
                    Native.stop()
                    WinTun.close()
                    return
                }
                if (prefs.keepAwake) WinTun.keepAwake(true)
                setupNetworkAsync(layout)
                applyFirewallChoice()
                startWatcher()
            } catch (t: Throwable) {
                Native.note("запуск туннеля: ${t.message}")
                TunnelController.onTunnelError(t.message ?: t.javaClass.simpleName)
                shutdown()
            }
        }

        /** Gives the adapter the virtual addresses. IPv4 is required, IPv6 is a bonus: its problems are only logged. */
        private fun applyAddresses(layout: NetLayout, mtu: Int) {
            // Phones send with their real address as the source: the PC answers through the adapter only if it has
            // a route to that address (the same mirrored addresses that the phone routes to the PC).
            val res = WinTun.configure(
                layout.my, layout.prefix, layout.my6, layout.prefix6, mtu, 1,
                layout.aliasRoutes.joinToString(","), layout.aliasRoutes6.joinToString(","),
            )
            val fatal = ArrayList<String>()
            for (line in res.lines()) {
                when {
                    line.startsWith("E:") -> fatal.add(line.substring(2))
                    line.startsWith("W:") -> Native.note("адаптер: " + line.substring(2))
                    line.startsWith("I:") -> Native.note("адаптер: " + line.substring(2))
                }
            }
            if (fatal.isNotEmpty()) throw IllegalStateException(fatal.joinToString("; "))
        }

        private fun describeTun(layout: NetLayout, fd: Int, mtu: Int): String =
            "адаптер Wintun «${WinTun.ADAPTER_NAME}» создан: fd=$fd, ${layout.my}/${layout.prefix}, MTU $mtu" +
                (if (layout.my6.isNotEmpty()) "; IPv6: ${layout.my6}/${layout.prefix6}" else "; IPv6 не включён") +
                (if (layout.group) "; группа, слот ${layout.slot}, версия сети ${layout.ver}" else "")

        // ------------------------------------------------------------------ firewall, host model, network profile

        private fun sh(cmd: String, timeoutMs: Int = 20000): Boolean {
            val (code, out) = WinTun.exec(cmd, timeoutMs)
            if (code != 0) Native.note("«${cmd.substringAfter(".exe\"").trim().take(90)}» → код $code ${out.trim().take(160)}")
            return code == 0
        }

        /**
         * Windows blocks unsolicited inbound traffic on the profile it gives a new adapter (public). The rules let in
         * everything that arrives through the adapter and the UDP of this program (the tunnel itself); the weak host
         * model lets the PC answer packets addressed to another of its addresses through the adapter.
         * Best effort and off the main path: the tunnel runs without any of it, the game may not.
         */
        private fun setupNetworkAsync(layout: NetLayout) {
            val gen = ++netSetupGen
            val t = Thread({
                // Another layout or a stop replaced this setup: whatever is left to do belongs to the newer one.
                fun stale(): Boolean = gen != netSetupGen || stopping.get()
                try {
                    val netsh = "\"${WinTun.system32("netsh.exe")}\""
                    val ps = "\"${WinTun.system32("WindowsPowerShell\\v1.0\\powershell.exe")}\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command"
                    val name = WinTun.ADAPTER_NAME
                    // Weak host model first (it decides whether the game works at all): the PC answers a packet that
                    // arrives through the adapter for another of its addresses. The interface name is a positional
                    // argument: the keyword differs between "ipv4" (name=) and "ipv6" (interface=). PowerShell is the
                    // fallback.
                    for (family in listOf("ipv4", "ipv6")) {
                        if (family == "ipv6" && layout.my6.isEmpty()) continue
                        if (stale()) return@Thread
                        val ok = sh("$netsh interface $family set interface \"$name\" weakhostreceive=enabled weakhostsend=enabled")
                        if (!ok) {
                            val fam = if (family == "ipv4") "IPv4" else "IPv6"
                            val fb = sh("$ps \"Set-NetIPInterface -InterfaceAlias '$name' -AddressFamily $fam -WeakHostSend Enabled -WeakHostReceive Enabled\"")
                            Native.note("weak host $fam: " + (if (fb) "включён через PowerShell" else "НЕ включён"))
                        } else {
                            Native.note("weak host $family: включён")
                        }
                    }
                    // Who may send to this PC through the adapter: the virtual subnets and the real addresses of the
                    // other devices (a phone's packets carry its real address as the source).
                    val remote = ArrayList<String>()
                    remote.add("${layout.net}/${layout.prefix}")
                    if (layout.net6.isNotEmpty()) remote.add("${layout.net6}/${layout.prefix6}")
                    for (a in layout.aliasRoutes) remote.add("$a/32")
                    for (a in layout.aliasRoutes6) remote.add("$a/128")
                    if (stale()) return@Thread
                    sh("$netsh advfirewall firewall delete rule name=\"$RULE_NET\"")
                    val ruleOk = sh("$netsh advfirewall firewall add rule name=\"$RULE_NET\" dir=in action=allow protocol=any profile=any remoteip=${remote.joinToString(",")}")
                    // Everything that arrives through the adapter, whatever its source address: the list above misses
                    // addresses of devices that joined later. Windows may not know a new adapter by its name for a few
                    // seconds, so this is tried again.
                    sh("$netsh advfirewall firewall delete rule name=\"$RULE_IFACE\"")
                    var ifaceOk = false
                    for (i in 0 until 5) {
                        if (stale()) break
                        ifaceOk = sh("$ps \"New-NetFirewallRule -DisplayName '$RULE_IFACE' -Direction Inbound -Action Allow -Profile Any -InterfaceAlias '$name' | Out-Null\"")
                        if (ifaceOk) break
                        Thread.sleep(2000)
                    }
                    val exe = ProcessHandle.current().info().command().orElse(null)
                    if (!stale() && exe != null && !exe.lowercase().endsWith("\\java.exe") && !exe.lowercase().endsWith("\\javaw.exe")) {
                        sh("$netsh advfirewall firewall delete rule name=\"$RULE_PROGRAM\"")
                        sh("$netsh advfirewall firewall add rule name=\"$RULE_PROGRAM\" dir=in action=allow protocol=udp profile=any program=\"$exe\"")
                    }
                    if (stopping.get()) {
                        // the tunnel was closed while the rules were being added: nothing may stay behind
                        removeFirewallRules()
                        return@Thread
                    }
                    Native.note(
                        "брандмауэр: правило по адресам " + (if (ruleOk) "добавлено (${remote.size} адресов и сетей)" else "НЕ добавлено") +
                            "; правило для всего адаптера " + (if (ifaceOk) "добавлено" else "НЕ добавлено"),
                    )
                    // A new adapter is a "public" network until Windows has identified it; this takes a few seconds.
                    val cmd = "$ps \"Get-NetConnectionProfile -InterfaceAlias '$name' | Set-NetConnectionProfile -NetworkCategory Private\""
                    var private = false
                    for (i in 0 until 8) {
                        if (stale()) return@Thread
                        if (WinTun.exec(cmd, 20000).first == 0) {
                            private = true
                            break
                        }
                        Thread.sleep(2500)
                    }
                    Native.note("сеть адаптера: " + (if (private) "частная" else "профиль не изменён (остаётся общедоступной)"))
                } catch (_: InterruptedException) {
                } catch (t: Throwable) {
                    Native.note("настройка брандмауэра: ${t.message}")
                }
            }, "lanbridge-firewall")
            t.isDaemon = true
            t.start()
        }

        // ------------------------------------------------------------------ Windows Firewall on/off (the user's choice)

        fun applyFirewallChoice() {
            val t = Thread({
                try {
                    synchronized(firewallLock) {
                        val off = Prefs(Context()).firewallMode == Prefs.FIREWALL_OFF
                        if (!off) {
                            FirewallGuard.restore().takeIf { it.isNotEmpty() }?.let { Native.note(it) }
                        } else if (started.get() && !stopping.get()) {
                            if (WinTun.isElevated()) Native.note(FirewallGuard.disable())
                            else Native.note("брандмауэр: нужны права администратора, не трогаю")
                            // the tunnel was closed while the firewall was being switched: it goes back at once
                            if (stopping.get()) FirewallGuard.restore().takeIf { it.isNotEmpty() }?.let { Native.note(it) }
                        }
                        // chosen "off" but the tunnel is not open: it is switched when the tunnel starts
                    }
                } catch (t: Throwable) {
                    Native.note("брандмауэр: ${t.message}")
                }
            }, "lanbridge-fw-choice")
            t.isDaemon = true
            t.start()
        }

        fun recoverFirewall() {
            val t = Thread({
                try {
                    synchronized(firewallLock) {
                        if (!started.get() && FirewallGuard.hasPendingRestore() && WinTun.isElevated()) {
                            Native.note("брандмауэр: прошлый запуск не вернул его, возвращаю")
                            FirewallGuard.restore().takeIf { it.isNotEmpty() }?.let { Native.note(it) }
                        }
                    }
                } catch (t: Throwable) {
                    Native.note("брандмауэр: ${t.message}")
                }
            }, "lanbridge-fw-recover")
            t.isDaemon = true
            t.start()
        }

        /** The end of the tunnel: the firewall is as the user had it (also after a crash of an earlier run). */
        private fun restoreFirewall() {
            try {
                synchronized(firewallLock) {
                    FirewallGuard.restore().takeIf { it.isNotEmpty() }?.let { Native.note(it) }
                }
            } catch (_: Throwable) {
            }
        }

        private fun removeFirewallRules() {
            try {
                val netsh = "\"${WinTun.system32("netsh.exe")}\""
                WinTun.exec("$netsh advfirewall firewall delete rule name=\"$RULE_NET\"", 15000)
                WinTun.exec("$netsh advfirewall firewall delete rule name=\"$RULE_PROGRAM\"", 15000)
                WinTun.exec("$netsh advfirewall firewall delete rule name=\"$RULE_IFACE\"", 15000)
            } catch (_: Throwable) {
            }
        }

        // ------------------------------------------------------------------ layout changes, shutdown

        /**
         * A group changed its membership: the addresses of the network are different now, so the adapter is set up
         * again and the core gets a fresh descriptor, keeping its sessions with the other devices.
         * Returns true when the new setup is in place.
         */
        private fun relayout(layout: NetLayout): Boolean {
            val mtu = Prefs(Context()).mtu
            try {
                applyAddresses(layout, mtu)
            } catch (t: Throwable) {
                Native.note("пересборка адаптера: ${t.message}; остаётся прежний")
                return false
            }
            val fd = WinTun.swapPair()
            if (fd < 0) {
                Native.note("пересборка адаптера: ${WinTun.error()}")
                return false
            }
            val rc = Native.swapTun(fd)
            if (rc != 0) {
                Native.note("пересборка адаптера: ядро не приняло интерфейс (код $rc)")
                return false
            }
            Native.note(describeTun(layout, fd, mtu).replace("создан", "пересобран"))
            appliedVer = layout.ver
            setupNetworkAsync(layout)
            return true
        }

        /** Every half second: the layout of the network. A change is applied after 1.5 s of quiet. */
        private fun startWatcher() {
            val t = Thread({
                var seenVer = appliedVer
                var seenSince = 0L
                var retryAt = 0L
                try {
                    while (!stopping.get()) {
                        val now = System.currentTimeMillis()
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
            }, "lanbridge-layout")
            t.isDaemon = true
            watcher = t
            t.start()
        }

        @Synchronized
        fun shutdown() {
            if (!stopping.compareAndSet(false, true)) return
            netSetupGen++
            watcher?.interrupt()
            try {
                Native.stop()
            } catch (_: Throwable) {
            }
            try {
                WinTun.keepAwake(false)
                WinTun.close()
            } catch (_: Throwable) {
            }
            removeFirewallRules()
            restoreFirewall()
            TunnelController.onTunnelStopped()
            started.set(false)
        }

        fun describe(ui: UiState): String {
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
                    else -> ""
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
                else -> ""
            }
        }
    }
}

private const val RULE_NET = "LanBridge virtual network"
private const val RULE_PROGRAM = "LanBridge program"
private const val RULE_IFACE = "LanBridge adapter"
