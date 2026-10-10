package app.lanbridge.core

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import app.lanbridge.vpn.TunnelVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

enum class Phase { IDLE, PREPARING, READY, CONNECTING, CONNECTED, STALLED, FAILED }

data class NetLayout(
    val my: String,
    val peer: String,
    val net: String,
    val prefix: Int,
    val bcast: String,
    val initiator: Boolean,
    /** This device's real addresses that the friend routes to us (the first one becomes the tunnel's primary address). */
    val realMine: List<String> = emptyList(),
    /** The friend's real addresses mirrored by the engine. */
    val realPeer: List<String> = emptyList(),
    /** The subset of [realPeer] that is safe to route into the tunnel on this device. */
    val aliasRoutes: List<String> = emptyList(),
    // IPv6 runs in the same tunnel at the same time: a unique-local /64 plus mirrored real global/ULA addresses.
    val my6: String = "",
    val peer6: String = "",
    val net6: String = "",
    val prefix6: Int = 64,
    val realMine6: List<String> = emptyList(),
    val realPeer6: List<String> = emptyList(),
    val aliasRoutes6: List<String> = emptyList(),
)

data class FriendInfo(
    val name: String,
    val expiresAt: Long,
    val nat: Int,
    val candidates: List<String>,
)

data class Stats(
    val rxBytes: Long,
    val txBytes: Long,
    val rxPkts: Long,
    val txPkts: Long,
    val rttMs: Long,
    val sinceRxMs: Long,
    val connectedSec: Long,
    val pathLocal: Int,
    val bcastTx: Long,
    val bcastRx: Long,
    val mcastTx: Long,
    val mcastRx: Long,
    val authFail: Long,
    val punchRx: Long,
    val hsRx: Long,
    val dropped: Long,
    val mappingChanged: Boolean,
    val myNat: Int,
    val peerNat: Int,
    val peerLeft: Boolean,
)

data class UiState(
    val phase: Phase = Phase.IDLE,
    val busy: Boolean = false,
    val myCode: String? = null,
    val myExpiresAt: Long = 0L,
    val myNat: Int = 0,
    val myCandidates: List<String> = emptyList(),
    val stunAnswered: Int = 0,
    val friendText: String = "",
    val friend: FriendInfo? = null,
    val friendError: String? = null,
    val layout: NetLayout? = null,
    val stats: Stats? = null,
    val pathText: String = "",
    val error: String? = null,
    val hint: String? = null,
    val testResult: String? = null,
    val testing: Boolean = false,
)

/** Process-wide coordinator between the UI, the native engine and the VPN service. */
object TunnelController {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    private lateinit var appCtx: Context
    private lateinit var prefs: Prefs
    private var inited = false
    private var nativeError: String? = null

    @Volatile
    private var friendBlob: ByteArray? = null

    @Volatile
    var layout: NetLayout? = null

    private var lastPhase = Phase.IDLE
    private var connectingSince = 0L

    @Synchronized
    fun init(ctx: Context) {
        if (inited) return
        inited = true
        appCtx = ctx.applicationContext
        prefs = Prefs(appCtx)
        try {
            Native.note("LanBridge запущен: ${Build.MANUFACTURER} ${Build.MODEL}, Android ${Build.VERSION.RELEASE}")
        } catch (t: Throwable) {
            nativeError = t.message ?: t.javaClass.simpleName
            _ui.update { it.copy(error = "Нативная библиотека не загрузилась: $nativeError") }
            return
        }
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                try {
                    pollOnce()
                } catch (_: Throwable) {
                }
                delay(if (_ui.value.phase == Phase.IDLE) 1500L else 500L)
            }
        }
    }

    // ------------------------------------------------------------------ user actions

    fun createCode() {
        if (nativeError != null) return
        val cur = _ui.value
        if (cur.busy) return
        if (cur.phase == Phase.CONNECTING || cur.phase == Phase.CONNECTED || cur.phase == Phase.STALLED) return
        _ui.update {
            it.copy(
                busy = true, phase = Phase.PREPARING, error = null, hint = null, myCode = null,
                friend = null, friendError = null, testResult = null,
            )
        }
        scope.launch(Dispatchers.IO) {
            val ips = NetInfo.localAddresses(appCtx)
            Native.note("локальные адреса: ${ips.joinToString()}")
            val blob: ByteArray? = try {
                Native.prepare(
                    prefs.stunServers.toByteArray(Charsets.UTF_8),
                    ips.joinToString("\n").toByteArray(Charsets.UTF_8),
                    prefs.deviceName.toByteArray(Charsets.UTF_8),
                    prefs.ttlMin * 60,
                )
            } catch (t: Throwable) {
                Native.note("prepare: ${t.message}")
                null
            }
            if (blob == null) {
                val why = Native.text(Native.lastError()).ifBlank { "нет сети или сетевых адресов" }
                _ui.update { it.copy(busy = false, phase = Phase.IDLE, error = "Не удалось создать код: $why") }
                return@launch
            }
            val code = OfferCodec.encode(blob)
            val d = Native.kv(Native.describeOffer(blob))
            val info = Native.kv(Native.info())
            val expires = d["expires"]?.toLongOrNull() ?: 0L
            val nat = d["nat"]?.toIntOrNull() ?: 0
            val cands = parseCands(d["cands"])
            val stun = info["stun"]?.toIntOrNull() ?: 0
            _ui.update {
                it.copy(
                    busy = false, phase = Phase.READY, myCode = code, myExpiresAt = expires, myNat = nat,
                    myCandidates = cands, stunAnswered = stun, error = null,
                )
            }
            validateFriend(_ui.value.friendText)
        }
    }

    fun setFriendText(text: String) {
        _ui.update { it.copy(friendText = text) }
        validateFriend(text)
    }

    fun reportError(msg: String) {
        _ui.update { it.copy(error = msg) }
    }

    fun clearError() {
        _ui.update { it.copy(error = null) }
    }

    /** Registers the friend's code in the engine and computes the shared network. Returns an error text or null. */
    fun prepareConnect(): String? {
        if (nativeError != null) return "Нативная библиотека не загружена"
        val blob = friendBlob ?: return "Введите код друга"
        val rc = Native.setPeer(blob)
        if (rc != 0) return offerErrorText(rc)
        val parsed = parseLayout(Native.kv(Native.layout())) ?: return "Не удалось вычислить адреса сети"
        // Never take over the gateway, a DNS server or an own address of this device with a mirrored route.
        val keep = NetInfo.sensitiveAddresses(appCtx)
        val l = parsed.copy(
            aliasRoutes = parsed.realPeer.filter { it !in keep },
            aliasRoutes6 = parsed.realPeer6.filter { NetInfo.canon(it) !in keep },
        )
        Native.note("зеркалируемые адреса друга: ${l.realPeer.joinToString()}; маршруты: ${l.aliasRoutes.joinToString()}; мои: ${l.realMine.joinToString()}")
        Native.note("IPv6: сеть ${l.net6}/${l.prefix6}, мой ${l.my6}, друг ${l.peer6}; адреса друга: ${l.realPeer6.joinToString()}; маршруты: ${l.aliasRoutes6.joinToString()}; мои: ${l.realMine6.joinToString()}")
        layout = l
        _ui.update { it.copy(layout = l, error = null, hint = null, testResult = null) }
        return null
    }

    fun retry() {
        connectingSince = SystemClock.elapsedRealtime()
        scope.launch(Dispatchers.IO) { Native.retry() }
    }

    fun disconnect(ctx: Context) {
        val p = _ui.value.phase
        if (p == Phase.CONNECTING || p == Phase.CONNECTED || p == Phase.STALLED || p == Phase.FAILED) {
            try {
                ctx.startService(Intent(ctx, TunnelVpnService::class.java).setAction(TunnelVpnService.ACTION_STOP))
                return
            } catch (_: Exception) {
            }
        }
        resetAll()
    }

    fun resetAll() {
        scope.launch(Dispatchers.IO) {
            LanSelfTest.stopResponder()
            Native.stop()
            clearUi()
        }
    }

    fun runLanTest() {
        val l = layout ?: return
        if (_ui.value.testing) return
        _ui.update { it.copy(testing = true, testResult = null) }
        scope.launch(Dispatchers.IO) {
            val res = try {
                LanSelfTest.run(l)
            } catch (t: Throwable) {
                "Проверка не выполнена: ${t.message}"
            }
            _ui.update { it.copy(testing = false, testResult = res) }
        }
    }

    // ------------------------------------------------------------------ service callbacks

    fun onTunnelStopped() {
        LanSelfTest.stopResponder()
        clearUi()
    }

    fun onTunnelError(msg: String) {
        _ui.update { it.copy(error = "Туннель не запущен: $msg") }
    }

    // ------------------------------------------------------------------ internals

    private fun clearUi() {
        friendBlob = null
        layout = null
        _ui.update {
            it.copy(
                phase = Phase.IDLE, busy = false, myCode = null, myExpiresAt = 0L, myCandidates = emptyList(),
                friendText = "", friend = null, friendError = null, layout = null, stats = null, pathText = "",
                hint = null, testResult = null, testing = false,
            )
        }
    }

    private fun validateFriend(text: String) {
        if (nativeError != null) return
        if (text.isBlank()) {
            friendBlob = null
            _ui.update { it.copy(friend = null, friendError = null) }
            return
        }
        val blob = OfferCodec.extract(text)
        if (blob == null) {
            friendBlob = null
            val msg = if (OfferCodec.isLegacy(text)) {
                "Код от версии 1.x. Обновите приложение у обоих и создайте коды заново"
            } else {
                "В тексте нет кода (он начинается с ${OfferCodec.PREFIX})"
            }
            _ui.update { it.copy(friend = null, friendError = msg) }
            return
        }
        val d = Native.kv(Native.describeOffer(blob))
        val rc = d["code"]?.toIntOrNull() ?: 1
        if (rc != 0) {
            friendBlob = null
            _ui.update { it.copy(friend = null, friendError = offerErrorText(rc)) }
            return
        }
        friendBlob = blob
        val f = FriendInfo(
            name = d["name"] ?: "",
            expiresAt = d["expires"]?.toLongOrNull() ?: 0L,
            nat = d["nat"]?.toIntOrNull() ?: 0,
            candidates = parseCands(d["cands"]),
        )
        _ui.update { it.copy(friend = f, friendError = null) }
    }

    private fun offerErrorText(rc: Int): String = when (rc) {
        1 -> "Код повреждён или обрезан"
        2 -> "Код повреждён: не сошлась контрольная сумма"
        3 -> "Код друга истёк — пусть создаст новый"
        4 -> "Это ваш собственный код"
        5 -> "Код создан другой сборкой приложения (формат кода изменился: добавлен IPv6). Установите одну и ту же свежую сборку у обоих и создайте коды заново"
        6 -> "Сначала создайте свой код"
        7 -> "В коде нет адресов"
        8 -> "Ваш код истёк — создайте новый"
        else -> "Ошибка кода ($rc)"
    }

    private fun parseCands(s: String?): List<String> = splitList(s)

    private fun splitList(s: String?): List<String> =
        if (s.isNullOrBlank()) emptyList() else s.split(',').filter { it.isNotBlank() }

    private fun parseLayout(m: Map<String, String>): NetLayout? {
        val my = m["my"] ?: return null
        val peer = m["peer"] ?: return null
        val net = m["net"] ?: return null
        return NetLayout(
            my = my,
            peer = peer,
            net = net,
            prefix = m["prefix"]?.toIntOrNull() ?: 24,
            bcast = m["bcast"] ?: return null,
            initiator = m["initiator"] == "1",
            realMine = splitList(m["realMine"]),
            realPeer = splitList(m["realPeer"]),
            my6 = m["my6"] ?: "",
            peer6 = m["peer6"] ?: "",
            net6 = m["net6"] ?: "",
            prefix6 = m["prefix6"]?.toIntOrNull() ?: 64,
            realMine6 = splitList(m["realMine6"]),
            realPeer6 = splitList(m["realPeer6"]),
        )
    }

    private fun hintFor(s: Stats, elapsedMs: Long): String? {
        if (elapsedMs < 12000L) return null
        return when {
            s.authFail > 0 ->
                "Пакеты друга приходят, но не проходят проверку: коды из разных сессий. Создайте новые коды у обоих."
            s.punchRx == 0L && s.hsRx == 0L && (s.myNat == 2 || s.peerNat == 2) ->
                "Пакеты друга не доходят. Один из NAT симметричный — прямое соединение вряд ли возможно. " +
                    "Вариант: оба в одном Wi-Fi или один раздаёт точку доступа."
            s.punchRx == 0L && s.hsRx == 0L ->
                "Пакеты друга не доходят. Друг должен нажать «Подключиться» и ввести именно ваш код; " +
                    "возможно, мешает NAT оператора."
            s.hsRx == 0L ->
                "Пробные пакеты идут только в одну сторону: ваш NAT или файрвол не пропускает ответ."
            else -> null
        }
    }

    private fun pollOnce() {
        val st = Native.status() ?: return
        if (st.size < 23) return
        val state = st[0].toInt()
        val info = Native.kv(Native.info())
        val stats = Stats(
            rxBytes = st[1], txBytes = st[2], rxPkts = st[3], txPkts = st[4], rttMs = st[5], sinceRxMs = st[6],
            connectedSec = st[7], pathLocal = st[8].toInt(), bcastTx = st[9], bcastRx = st[10], mcastTx = st[11],
            mcastRx = st[12], authFail = st[13], punchRx = st[14], hsRx = st[15], dropped = st[16],
            mappingChanged = st[17] != 0L, myNat = st[18].toInt(), peerNat = st[19].toInt(), peerLeft = st[22] != 0L,
        )
        val phase = when (state) {
            1 -> Phase.PREPARING
            2 -> Phase.READY
            3 -> Phase.CONNECTING
            4 -> Phase.CONNECTED
            5 -> Phase.STALLED
            6 -> Phase.FAILED
            else -> Phase.IDLE
        }
        val now = SystemClock.elapsedRealtime()
        if (phase == Phase.CONNECTING && lastPhase != Phase.CONNECTING) connectingSince = now
        val hint = if (phase == Phase.CONNECTING || phase == Phase.FAILED) hintFor(stats, now - connectingSince) else null
        val nativeErr = if (phase == Phase.FAILED) Native.text(Native.lastError()) else ""
        _ui.update { cur ->
            if (cur.busy) {
                cur.copy(stats = stats)
            } else {
                cur.copy(
                    phase = phase,
                    stats = stats,
                    pathText = info["path"] ?: "",
                    hint = hint,
                    error = if (nativeErr.isNotBlank()) nativeErr else cur.error,
                )
            }
        }
        val old = lastPhase
        if (phase != old && !_ui.value.busy) {
            lastPhase = phase
            val wasUp = old == Phase.CONNECTED || old == Phase.STALLED
            if (phase == Phase.CONNECTED && old != Phase.STALLED) {
                val l = layout
                if (l != null) LanSelfTest.startResponder(l, prefs.deviceName)
            } else if (wasUp && phase != Phase.CONNECTED && phase != Phase.STALLED) {
                LanSelfTest.stopResponder()
            }
            if (phase == Phase.IDLE && old != Phase.IDLE) clearUi()
        }
    }
}
