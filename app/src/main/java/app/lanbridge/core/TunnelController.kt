package app.lanbridge.core

import android.content.Context
import android.content.Intent
import android.os.SystemClock
import app.lanbridge.ui.Fmt
import app.lanbridge.ui.SysActions
import app.lanbridge.vpn.TunnelVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

enum class Phase { IDLE, PREPARING, READY, CONNECTING, CONNECTED, STALLED, FAILED }

/** What the main screen offers: a group of up to 8 devices (one code) or a direct connection of two (codes both ways). */
enum class Mode { GROUP, DIRECT }

data class NetLayout(
    val my: String,
    /** The first other device (direct mode: the friend); empty while a group has nobody but the creator. */
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
    /** Version of the layout in the core: the TUN has to be set up again when it moves (a member came or went). */
    val ver: Long = 0L,
    /** This device's place in the group (1 = the creator); 0 in direct mode. */
    val slot: Int = 0,
    val group: Boolean = false,
)

data class FriendInfo(
    val name: String,
    val expiresAt: Long,
    val nat: Int,
    val candidates: List<String>,
    val families: Int = 0,  // bit 0: reachable over IPv4, bit 1: over IPv6
    val isGroup: Boolean = false,
    val maxMembers: Int = 0,
)

/** One of the other devices of the network (the friend in direct mode). */
data class Member(
    val slot: Int,
    val name: String,
    /** 1 connecting, 2 connected, 3 silent, 4 left */
    val state: Int,
    val rttMs: Long,
    /** 0 none, 1 internet, 2 local network, 3 through the creator */
    val pathKind: Int,
    val pathText: String,
    val ip4: String,
    val ip6: String,
    val profVer: Long,
    val isCreator: Boolean,
    val rxBytes: Long,
    val txBytes: Long,
    val connectedSec: Long,
    val families: Int,
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
    val relayed: Long = 0L,
)

data class UiState(
    val phase: Phase = Phase.IDLE,
    val mode: Mode = Mode.GROUP,
    val busy: Boolean = false,
    /** The code to hand out: the own direct code, or the group code of the creator. */
    val myCode: String? = null,
    val myExpiresAt: Long = 0L,
    val myNat: Int = 0,
    val myFamilies: Int = 0,  // bit 0: IPv4, bit 1: IPv6 (what the tunnel's sockets and addresses allow)
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
    // ---- groups
    val groupRole: Int = 0,        // 0 none, 1 creator, 2 member
    val joining: Boolean = false,  // a newcomer is on its way into a group (until the tunnel is up)
    val joinReady: Boolean = false, // admitted and the member list is complete: the screen starts the VPN
    val joinState: Int = 0,        // 0 none, 1 knocking, 2 admitted, 3 refused
    val mySlot: Int = 0,
    val groupMax: Int = 8,
    val members: List<Member> = emptyList(),
    val membersKnown: Int = 0,     // devices of the network besides this one
    val membersUp: Int = 0,        // of them connected right now
    val myProfileName: String = "",
    val myAvatar: ByteArray = ByteArray(0),
    val avatars: Map<Int, ByteArray> = emptyMap(),  // by slot
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
    private var hintJob: Job? = null

    private var joinAdmittedAt = 0L
    private var joinReadyAt = 0L
    private val avatarKey = HashMap<Int, String>()  // slot -> "profVer|name" of the avatar in [avatarCache]
    private val avatarCache = HashMap<Int, ByteArray>()

    @Synchronized
    fun init(ctx: Context) {
        if (inited) return
        inited = true
        appCtx = ctx.applicationContext
        prefs = Prefs(appCtx)
        _ui.update { it.copy(mode = if (prefs.groupMode) Mode.GROUP else Mode.DIRECT) }
        try {
            Native.note("LanBridge запущен: ${SysActions.platformLabel()}")
        } catch (t: Throwable) {
            nativeError = t.message ?: t.javaClass.simpleName
            _ui.update { it.copy(error = "Нативная библиотека не загрузилась: $nativeError") }
            return
        }
        applyProfile()
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

    // ------------------------------------------------------------------ profile (name and avatar)

    /** Hands the name and the avatar from the settings to the core, which sends them to the other participants. */
    fun applyProfile() {
        if (nativeError != null) return
        val name = prefs.deviceName
        val avatar = prefs.avatar
        _ui.update { it.copy(myProfileName = name, myAvatar = avatar) }
        try {
            Native.setProfile(name.toByteArray(Charsets.UTF_8), avatar)
        } catch (t: Throwable) {
            Native.note("setProfile: ${t.message}")
        }
    }

    // ------------------------------------------------------------------ user actions

    /** Switches between a group and a direct connection (only while nothing is running). */
    fun setMode(m: Mode, keepText: Boolean = false) {
        val cur = _ui.value
        if (cur.mode == m || cur.busy || cur.joining) return
        val p = cur.phase
        if (p == Phase.CONNECTING || p == Phase.CONNECTED || p == Phase.STALLED || p == Phase.FAILED) return
        prefs.groupMode = m == Mode.GROUP
        val text = if (keepText) cur.friendText else ""
        scope.launch(Dispatchers.IO) {
            stopHintJob()
            if (nativeError == null) {
                try {
                    Native.stop()
                } catch (_: Throwable) {
                }
            }
            clearUi()
            _ui.update { it.copy(mode = m) }
            if (text.isNotEmpty()) setFriendText(text)
        }
    }

    /** Direct mode: a one-time code of this device. */
    fun createCode() {
        if (nativeError != null) return
        val cur = _ui.value
        if (cur.busy || cur.joining) return
        if (cur.phase == Phase.CONNECTING || cur.phase == Phase.CONNECTED || cur.phase == Phase.STALLED) return
        _ui.update {
            it.copy(
                busy = true, phase = Phase.PREPARING, error = null, hint = null, myCode = null,
                friend = null, friendError = null, testResult = null,
            )
        }
        scope.launch(Dispatchers.IO) {
            stopHintJob()
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
            applyProfile()
            val code = OfferCodec.encode(blob)
            val d = Native.kv(Native.describeOffer(blob))
            val info = Native.kv(Native.info())
            val expires = d["expires"]?.toLongOrNull() ?: 0L
            val nat = d["nat"]?.toIntOrNull() ?: 0
            val cands = parseCands(d["cands"])
            val stun = info["stun"]?.toIntOrNull() ?: 0
            val fam = d["families"]?.toIntOrNull() ?: 0
            Native.note("транспорт: IPv4 ${info["transport4"] ?: "?"}, IPv6 ${info["transport6"] ?: "?"}; код доступен по: ${Fmt.families(fam)}")
            _ui.update {
                it.copy(
                    busy = false, phase = Phase.READY, myCode = code, myExpiresAt = expires, myNat = nat,
                    myFamilies = fam, myCandidates = cands, stunAnswered = stun, error = null,
                )
            }
            validateFriend(_ui.value.friendText)
        }
    }

    /** Group mode, creator: a one-time group code. Members join with it alone, nothing is sent back. */
    fun createGroup() {
        if (nativeError != null) return
        val cur = _ui.value
        if (cur.busy || cur.joining) return
        if (cur.phase == Phase.CONNECTING || cur.phase == Phase.CONNECTED || cur.phase == Phase.STALLED) return
        _ui.update {
            it.copy(
                busy = true, phase = Phase.PREPARING, error = null, hint = null, myCode = null,
                testResult = null, members = emptyList(), membersKnown = 0, membersUp = 0,
            )
        }
        scope.launch(Dispatchers.IO) {
            stopHintJob()
            val ips = NetInfo.localAddresses(appCtx)
            Native.note("локальные адреса: ${ips.joinToString()}")
            val blob: ByteArray? = try {
                Native.prepareGroup(
                    prefs.stunServers.toByteArray(Charsets.UTF_8),
                    ips.joinToString("\n").toByteArray(Charsets.UTF_8),
                    prefs.deviceName.toByteArray(Charsets.UTF_8),
                    prefs.ttlMin * 60,
                )
            } catch (t: Throwable) {
                Native.note("prepareGroup: ${t.message}")
                null
            }
            if (blob == null) {
                val why = Native.text(Native.lastError()).ifBlank { "нет сети или сетевых адресов" }
                _ui.update { it.copy(busy = false, phase = Phase.IDLE, error = "Не удалось создать группу: $why") }
                return@launch
            }
            applyProfile()
            val d = Native.kv(Native.describeOffer(blob))
            val info = Native.kv(Native.info())
            val fam = d["families"]?.toIntOrNull() ?: 0
            Native.note("группа создана: IPv4 ${info["transport4"] ?: "?"}, IPv6 ${info["transport6"] ?: "?"}; код доступен по: ${Fmt.families(fam)}")
            _ui.update {
                it.copy(
                    busy = false, phase = Phase.READY, myCode = OfferCodec.encodeGroup(blob),
                    myExpiresAt = d["expires"]?.toLongOrNull() ?: 0L, myNat = d["nat"]?.toIntOrNull() ?: 0,
                    myFamilies = fam, myCandidates = parseCands(d["cands"]),
                    stunAnswered = info["stun"]?.toIntOrNull() ?: 0, groupRole = 1, error = null,
                )
            }
            startHintReader()
        }
    }

    /** Creator: the same group with a fresh code (the old one runs out, the new one is valid for the set time). */
    fun renewGroup() {
        if (nativeError != null || _ui.value.groupRole != 1) return
        scope.launch(Dispatchers.IO) {
            val blob: ByteArray? = try {
                Native.renewGroup(prefs.ttlMin * 60)
            } catch (t: Throwable) {
                Native.note("renewGroup: ${t.message}")
                null
            }
            if (blob == null) {
                _ui.update { it.copy(error = "Не удалось продлить код группы") }
                return@launch
            }
            val d = Native.kv(Native.describeOffer(blob))
            _ui.update {
                it.copy(myCode = OfferCodec.encodeGroup(blob), myExpiresAt = d["expires"]?.toLongOrNull() ?: it.myExpiresAt)
            }
        }
    }

    /** Group creator: works out the network the tunnel is made with. Returns an error text or null. */
    fun prepareStartGroup(): String? {
        if (nativeError != null) return "Нативная библиотека не загружена"
        val l = fetchLayout() ?: return "Не удалось вычислить адреса сети"
        adoptLayout(l)
        return null
    }

    /**
     * Group member: joins the group of the pasted code. Admission happens in the background; when it is complete
     * [UiState.joinReady] turns on and the screen starts the VPN.
     */
    fun joinGroup() {
        if (nativeError != null) return
        val cur = _ui.value
        if (cur.busy || cur.joining) return
        val blob = friendBlob
        if (blob == null || cur.friend?.isGroup != true) {
            reportError("Вставьте код группы")
            return
        }
        joinAdmittedAt = 0L
        joinReadyAt = 0L
        _ui.update {
            it.copy(
                busy = true, joining = true, joinReady = false, phase = Phase.PREPARING, error = null, hint = null,
                testResult = null, members = emptyList(), membersKnown = 0, membersUp = 0, myCode = null,
            )
        }
        scope.launch(Dispatchers.IO) {
            stopHintJob()
            LanSelfTest.stopResponder()
            try {
                Native.stop()
            } catch (_: Throwable) {
            }
            val ips = NetInfo.localAddresses(appCtx)
            Native.note("локальные адреса: ${ips.joinToString()}")
            val own: ByteArray? = try {
                Native.prepare(
                    prefs.stunServers.toByteArray(Charsets.UTF_8),
                    ips.joinToString("\n").toByteArray(Charsets.UTF_8),
                    prefs.deviceName.toByteArray(Charsets.UTF_8),
                    maxOf(prefs.ttlMin, 10) * 60,
                )
            } catch (t: Throwable) {
                Native.note("prepare: ${t.message}")
                null
            }
            if (own == null) {
                val why = Native.text(Native.lastError()).ifBlank { "нет сети или сетевых адресов" }
                failJoin("Не удалось подключиться: $why")
                return@launch
            }
            applyProfile()
            val rc = try {
                Native.joinGroup(blob)
            } catch (t: Throwable) {
                Native.note("joinGroup: ${t.message}")
                -1
            }
            if (rc != 0) {
                failJoin(if (rc < 0) "Не удалось войти в группу" else offerErrorText(rc))
                return@launch
            }
            _ui.update { it.copy(busy = false, phase = Phase.READY) }
            startHintSender()
        }
    }

    /** The screen has taken the "admitted" signal and is starting the VPN. */
    fun consumeJoinReady() {
        _ui.update { if (it.joinReady) it.copy(joinReady = false) else it }
        joinReadyAt = SystemClock.elapsedRealtime()
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

    /** Direct mode: registers the friend's code in the engine and computes the shared network. Returns an error text or null. */
    fun prepareConnect(): String? {
        if (nativeError != null) return "Нативная библиотека не загружена"
        val blob = friendBlob ?: return "Введите код друга"
        val rc = Native.setPeer(blob)
        if (rc != 0) return offerErrorText(rc)
        val l = fetchLayout() ?: return "Не удалось вычислить адреса сети"
        Native.note("зеркалируемые адреса друга: ${l.realPeer.joinToString()}; маршруты: ${l.aliasRoutes.joinToString()}; мои: ${l.realMine.joinToString()}")
        Native.note("IPv6: сеть ${l.net6}/${l.prefix6}, мой ${l.my6}, друг ${l.peer6}; адреса друга: ${l.realPeer6.joinToString()}; маршруты: ${l.aliasRoutes6.joinToString()}; мои: ${l.realMine6.joinToString()}")
        adoptLayout(l)
        _ui.update { it.copy(error = null, hint = null, testResult = null) }
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
            stopHintJob()
            LanSelfTest.stopResponder()
            Native.stop()
            clearUi()
        }
    }

    fun runLanTest() {
        val l = layout ?: return
        if (_ui.value.testing) return
        if (l.peer.isEmpty()) {
            _ui.update { it.copy(testResult = "\nНет других участников: проверять не с кем") }
            return
        }
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
        stopHintJob()
        LanSelfTest.stopResponder()
        clearUi()
    }

    fun onTunnelError(msg: String) {
        _ui.update { it.copy(error = "Туннель не запущен: $msg") }
        if (_ui.value.joining) resetAll()
    }

    // ------------------------------------------------------------------ internals

    private fun stopHintJob() {
        hintJob?.cancel()
        hintJob = null
    }

    private fun clearUi() {
        friendBlob = null
        layout = null
        joinAdmittedAt = 0L
        joinReadyAt = 0L
        avatarKey.clear()
        avatarCache.clear()
        _ui.update {
            it.copy(
                phase = Phase.IDLE, busy = false, myCode = null, myExpiresAt = 0L, myFamilies = 0, myCandidates = emptyList(),
                friendText = "", friend = null, friendError = null, layout = null, stats = null, pathText = "",
                hint = null, testResult = null, testing = false,
                groupRole = 0, joining = false, joinReady = false, joinState = 0, mySlot = 0, members = emptyList(),
                membersKnown = 0, membersUp = 0, avatars = emptyMap(),
            )
        }
    }

    private fun failJoin(msg: String) {
        stopHintJob()
        LanSelfTest.stopResponder()
        try {
            Native.stop()
        } catch (_: Throwable) {
        }
        joinAdmittedAt = 0L
        joinReadyAt = 0L
        _ui.update {
            it.copy(
                joining = false, joinReady = false, busy = false, phase = Phase.IDLE, error = msg, joinState = 0,
                groupRole = 0, mySlot = 0, members = emptyList(), membersKnown = 0, membersUp = 0, avatars = emptyMap(),
            )
        }
    }

    private fun adoptLayout(l: NetLayout) {
        layout = l
        _ui.update { it.copy(layout = l) }
    }

    /** The virtual network as the core describes it now, with the mirrored routes that are safe on this device. */
    fun fetchLayout(): NetLayout? {
        val parsed = parseLayout(Native.kv(Native.netLayout())) ?: return null
        // Never take over the gateway, a DNS server or an own address of this device with a mirrored route.
        val keep = NetInfo.sensitiveAddresses(appCtx)
        return parsed.copy(
            aliasRoutes = parsed.realPeer.filter { it !in keep },
            aliasRoutes6 = parsed.realPeer6.filter { NetInfo.canon(it) !in keep },
        )
    }

    private fun validateFriend(text: String) {
        if (nativeError != null) return
        if (text.isBlank()) {
            friendBlob = null
            _ui.update { it.copy(friend = null, friendError = null) }
            return
        }
        val readings = OfferCodec.candidates(text)
        if (readings.isEmpty()) {
            friendBlob = null
            logFriendText("в тексте (${text.length} симв.) кода нет")
            val msg = if (OfferCodec.isLegacy(text)) {
                "Код от версии 1.x. Обновите приложение у обоих и создайте коды заново"
            } else {
                "В тексте нет кода (он начинается с ${OfferCodec.GROUP_PREFIX} или ${OfferCodec.PREFIX}). " +
                    "Скопируйте код целиком, вместе с началом, или отсканируйте QR"
            }
            _ui.update { it.copy(friend = null, friendError = msg) }
            return
        }
        // The text may hold more than one reading (a code split over lines, words after it, two codes): the core checks
        // the length and the checksum, so the first reading that is a whole code wins. A code that is only expired, own or
        // of another kind is still a whole code and gets its own message.
        var blob: ByteArray? = null
        var d: Map<String, String> = emptyMap()
        var rc = 1
        var chars = 0
        for (pass in 0..1) {
            for (r in readings) {
                val dd = Native.kv(Native.describeOffer(r.blob))
                val code = dd["code"]?.toIntOrNull() ?: 1
                val whole = code != 1 && code != 2
                if ((pass == 0 && code == 0) || (pass == 1 && whole)) {
                    blob = r.blob; d = dd; rc = code; chars = r.chars
                    break
                }
            }
            if (blob != null) break
        }
        if (blob == null) {
            // Nothing is a whole code: report the reading that got furthest (its length fits, only the sum is wrong).
            val best = readings.map { r -> r to (Native.kv(Native.describeOffer(r.blob))["code"]?.toIntOrNull() ?: 1) }
                .let { l -> l.firstOrNull { it.second == 2 } ?: l.first() }
            friendBlob = null
            logFriendText("прочитано ${best.first.chars} симв. кода, ошибка ${best.second}")
            _ui.update { it.copy(friend = null, friendError = offerErrorText(best.second, best.first.chars)) }
            return
        }
        if (rc != 0) {
            friendBlob = null
            logFriendText("код найден (${chars} симв.), ошибка $rc")
            _ui.update { it.copy(friend = null, friendError = offerErrorText(rc, chars)) }
            return
        }
        logFriendText("код принят (${chars} симв., в тексте ${text.length})")
        val isGroup = d["group"] == "1"
        val cur = _ui.value
        if (isGroup != (cur.mode == Mode.GROUP)) {
            // A code of the other kind: follow it when nothing of this device is made yet, otherwise say what is wrong.
            if (cur.myCode == null && !cur.busy && !cur.joining &&
                (cur.phase == Phase.IDLE || cur.phase == Phase.READY)
            ) {
                setMode(if (isGroup) Mode.GROUP else Mode.DIRECT, keepText = true)
                return
            }
            friendBlob = null
            val msg = if (isGroup) {
                "Это код группы. Сначала закройте свой код (кнопка «Отключить» или «Создать заново»)"
            } else {
                "Это код прямого соединения, а у вас создана группа. Сначала закройте группу"
            }
            _ui.update { it.copy(friend = null, friendError = msg) }
            return
        }
        val famFriend = d["families"]?.toIntOrNull() ?: 0
        if (!isGroup && d["common"] == "0") {
            // Our code and the friend's code share no protocol (one is IPv4-only, the other IPv6-only): the tunnel
            // could never come up, so say so now instead of after a timeout.
            friendBlob = null
            _ui.update {
                it.copy(
                    friend = null,
                    friendError = "Нет общего протокола: у вас ${Fmt.families(_ui.value.myFamilies)}, у друга ${Fmt.families(famFriend)}. " +
                        "Нужен хотя бы один общий (IPv4 или IPv6). Подключите телефон к другой сети (например, к общему Wi-Fi) " +
                        "и создайте код заново",
                )
            }
            return
        }
        friendBlob = blob
        val f = FriendInfo(
            name = d["name"] ?: "",
            expiresAt = d["expires"]?.toLongOrNull() ?: 0L,
            nat = d["nat"]?.toIntOrNull() ?: 0,
            candidates = parseCands(d["cands"]),
            families = famFriend,
            isGroup = isGroup,
            maxMembers = d["max"]?.toIntOrNull() ?: 0,
        )
        _ui.update { it.copy(friend = f, friendError = null) }
    }

    private var lastFriendLog = ""

    /** One line in the log per change of the verdict on the pasted text, so that a rejected code can be explained later. */
    private fun logFriendText(what: String) {
        if (what == lastFriendLog) return
        lastFriendLog = what
        Native.note("код друга: $what")
    }

    private fun offerErrorText(rc: Int, chars: Int = 0): String = when (rc) {
        1 -> "Код повреждён или обрезан" + (if (chars > 0) " (прочитано $chars символов после начала). Скопируйте его целиком или отсканируйте QR" else "")
        2 -> "Код повреждён: не сошлась контрольная сумма" + (if (chars > 0) " ($chars символов). Скопируйте код заново целиком или отсканируйте QR" else "")
        3 -> "Код истёк — пусть создаст новый"
        4 -> "Это ваш собственный код"
        5 -> "Код создан другой сборкой приложения (в сборке 20005 появились группы). Установите одну и ту же свежую сборку у всех и создайте коды заново"
        6 -> "Сначала создайте свой код"
        7 -> "В коде нет адресов"
        8 -> "Ваш код истёк — создайте новый"
        9 -> "Код другого вида: код группы вставляется в режиме «Группа», код двоих — в режиме «Вдвоём»"
        10 -> "Подключение уже идёт: отключитесь и повторите"
        else -> "Ошибка кода ($rc)"
    }

    private fun parseCands(s: String?): List<String> = splitList(s)

    private fun splitList(s: String?): List<String> =
        if (s.isNullOrBlank()) emptyList() else s.split(',').filter { it.isNotBlank() }

    private fun parseLayout(m: Map<String, String>): NetLayout? {
        val my = m["my"] ?: return null
        val peer = m["peer"] ?: ""
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
            ver = m["ver"]?.toLongOrNull() ?: 0L,
            slot = m["slot"]?.toIntOrNull() ?: 0,
            group = m["group"] == "1",
        )
    }

    private class MembersView(val mySlot: Int, val role: Int, val others: List<Member>)

    private fun parseMembers(text: String): MembersView? {
        var mine: List<String>? = null
        val others = ArrayList<Member>()
        for (line in text.split('\n')) {
            if (line.isEmpty()) continue
            val f = line.split('\t')
            if (f[0] == "S" && f.size >= 7) {
                mine = f
            } else if (f[0] == "M" && f.size >= 15) {
                others.add(
                    Member(
                        slot = f[1].toIntOrNull() ?: continue,
                        name = f[2],
                        state = f[3].toIntOrNull() ?: 1,
                        rttMs = f[4].toLongOrNull() ?: -1L,
                        pathKind = f[5].toIntOrNull() ?: 0,
                        pathText = f[6],
                        ip4 = f[7],
                        ip6 = f[8],
                        profVer = f[9].toLongOrNull() ?: 0L,
                        isCreator = f[10] == "1",
                        rxBytes = f[11].toLongOrNull() ?: 0L,
                        txBytes = f[12].toLongOrNull() ?: 0L,
                        connectedSec = f[13].toLongOrNull() ?: 0L,
                        families = f[14].toIntOrNull() ?: 0,
                    ),
                )
            }
        }
        val s = mine ?: return null
        return MembersView(mySlot = s[1].toIntOrNull() ?: 0, role = s[6].toIntOrNull() ?: 0, others = others)
    }

    /** Takes the member list of the core into the UI state, fetching the avatars that arrived. */
    private fun pollMembers() {
        val v = parseMembers(Native.text(Native.members())) ?: return
        var avatarsChanged = false
        val present = HashSet<Int>()
        for (m in v.others) {
            present.add(m.slot)
            if (m.profVer == 0L) continue
            val key = "${m.profVer}|${m.name}"
            if (avatarKey[m.slot] == key) continue
            avatarKey[m.slot] = key
            val bytes = Native.memberAvatar(m.slot)
            if (bytes != null && bytes.isNotEmpty()) avatarCache[m.slot] = bytes else avatarCache.remove(m.slot)
            avatarsChanged = true
        }
        val gone = avatarKey.keys.filter { it !in present }
        for (s in gone) {
            avatarKey.remove(s)
            avatarCache.remove(s)
            avatarsChanged = true
        }
        val up = v.others.count { it.state == 2 }
        val snapshot: Map<Int, ByteArray>? = if (avatarsChanged) HashMap(avatarCache) else null
        _ui.update { cur ->
            if (cur.members == v.others && snapshot == null && cur.membersUp == up && cur.mySlot == v.mySlot) {
                cur
            } else {
                cur.copy(
                    members = v.others, membersKnown = v.others.size, membersUp = up, mySlot = v.mySlot,
                    avatars = snapshot ?: cur.avatars,
                )
            }
        }
    }

    private fun hintFor(s: Stats, elapsedMs: Long): String? {
        if (elapsedMs < 12000L) return null
        val ui = _ui.value
        if (ui.groupRole != 0) {
            return when {
                ui.groupRole == 2 && ui.membersUp == 0 ->
                    "Создатель группы не отвечает. Проверьте, что он запустил группу, код не истёк и у всех одна сборка; " +
                        "при строгом NAT помогает IPv6 у обоих или один общий Wi-Fi."
                else -> null
            }
        }
        val v6Common = (ui.myFamilies and (ui.friend?.families ?: 0) and 2) != 0
        return when {
            s.authFail > 0 ->
                "Пакеты друга приходят, но не проходят проверку: коды из разных сессий. Создайте новые коды у обоих."
            s.punchRx == 0L && s.hsRx == 0L && (s.myNat == 2 || s.peerNat == 2) && !v6Common ->
                "Пакеты друга не доходят. Один из NAT (IPv4) симметричный — прямое соединение вряд ли возможно. " +
                    "Поможет IPv6 у обоих (включите IPv6 в сети или у оператора) или один Wi-Fi / точка доступа."
            s.punchRx == 0L && s.hsRx == 0L && v6Common ->
                "Пакеты друга не доходят ни по IPv4, ни по IPv6. Друг должен нажать «Подключиться» и ввести именно ваш код; " +
                    "возможно, файрвол роутера или NAT оператора блокирует входящий UDP."
            s.punchRx == 0L && s.hsRx == 0L ->
                "Пакеты друга не доходят. Друг должен нажать «Подключиться» и ввести именно ваш код; " +
                    "возможно, мешает NAT оператора."
            s.hsRx == 0L ->
                "Пробные пакеты идут только в одну сторону: ваш NAT или файрвол не пропускает ответ."
            else -> null
        }
    }

    // ------------------------------------------------------------------ strict NAT help (optional, best effort)

    /** Creator: reads the notes that newcomers leave on the message board and passes them to the core. */
    private fun startHintReader() {
        if (!prefs.hintMailbox) return
        stopHintJob()
        hintJob = scope.launch(Dispatchers.IO) {
            HintMailbox.reset()
            val topic = Native.text(Native.hintTopic())
            if (topic.isBlank()) return@launch
            while (isActive) {
                try {
                    for (note in HintMailbox.fetch(topic)) {
                        val n = Native.openHint(note)
                        if (n > 0) Native.note("записка новичка принята, адресов: $n")
                    }
                } catch (_: Throwable) {
                }
                delay(4000L)
            }
        }
    }

    /** Newcomer: leaves a few sealed notes while the creator has not let it in yet. */
    private fun startHintSender() {
        if (!prefs.hintMailbox) return
        stopHintJob()
        hintJob = scope.launch(Dispatchers.IO) {
            val topic = Native.text(Native.hintTopic())
            if (topic.isBlank()) return@launch
            var sent = 0
            while (isActive && sent < 8) {
                val note = try {
                    Native.sealHint()
                } catch (_: Throwable) {
                    null
                }
                if (note == null) break  // not knocking any more
                HintMailbox.post(topic, note)
                sent++
                delay(2500L)
            }
        }
    }

    // ------------------------------------------------------------------ polling

    /** Group: admission of a newcomer step by step, until the screen can start the VPN. */
    private fun joinProgress(st: LongArray, phase: Phase) {
        val ui = _ui.value
        if (!ui.joining || ui.busy) return
        val now = SystemClock.elapsedRealtime()
        if (phase == Phase.CONNECTING || phase == Phase.CONNECTED || phase == Phase.STALLED) {
            // the tunnel is up: the join is over
            joinAdmittedAt = 0L
            joinReadyAt = 0L
            _ui.update { it.copy(joining = false, joinReady = false) }
            return
        }
        if (st.size < 32) return
        val js = st[27].toInt()
        if (js == 3L.toInt()) {
            failJoin(Native.text(Native.lastError()).ifBlank { "Создатель группы не принял вход" })
            return
        }
        if (phase == Phase.IDLE) {
            failJoin("Подключение прервано")
            return
        }
        if (js == 2) {
            if (joinAdmittedAt == 0L) joinAdmittedAt = now
            if (!ui.joinReady && joinReadyAt == 0L) {
                val settled = st[31] == 1L
                if (settled || now - joinAdmittedAt > 6000L) {
                    val l = fetchLayout()
                    if (l == null) {
                        failJoin("Не удалось вычислить адреса сети")
                    } else {
                        layout = l
                        _ui.update { it.copy(joinReady = true, layout = l) }
                    }
                }
            } else if (joinReadyAt != 0L && now - joinReadyAt > 120000L) {
                failJoin("Не удалось запустить VPN")
            }
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
            relayed = if (st.size >= 31) st[30] else 0L,
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
        val role = if (st.size >= 32) st[26].toInt() else 0
        val joinState = if (st.size >= 32) st[27].toInt() else 0
        val now = SystemClock.elapsedRealtime()
        if (phase == Phase.CONNECTING && lastPhase != Phase.CONNECTING) connectingSince = now
        val nativeErr = if (phase == Phase.FAILED) Native.text(Native.lastError()) else ""
        _ui.update { cur ->
            if (cur.busy) {
                cur.copy(stats = stats)
            } else {
                // a phase that comes from the core must not drop the screen of a newcomer that is still joining
                cur.copy(
                    phase = phase,
                    stats = stats,
                    pathText = info["path"] ?: "",
                    error = if (nativeErr.isNotBlank()) nativeErr else cur.error,
                    groupRole = if (role != 0) role else if (cur.joining) 2 else 0,
                    joinState = joinState,
                    groupMax = info["maxMembers"]?.toIntOrNull() ?: cur.groupMax,
                )
            }
        }
        if (!_ui.value.busy) {
            val hint = if (phase == Phase.CONNECTING || phase == Phase.FAILED) hintFor(stats, now - connectingSince) else null
            _ui.update { it.copy(hint = hint) }
        }
        if (role != 0 && !_ui.value.busy && phase != Phase.IDLE) {
            pollMembers()
            // the members changed what the TUN has to be set up with: the service builds it again from the new layout
            val l = layout
            if (l != null && st.size >= 24 && st[23] != l.ver) {
                val fresh = fetchLayout()
                if (fresh != null) {
                    layout = fresh
                    _ui.update { it.copy(layout = fresh) }
                    if (phase == Phase.CONNECTED) LanSelfTest.startResponder(fresh, prefs.deviceName)
                }
            }
        } else if (role == 0 && !_ui.value.joining) {
            // direct mode: the friend's name and avatar come from the same member list
            if (phase == Phase.CONNECTING || phase == Phase.CONNECTED || phase == Phase.STALLED) pollMembers()
        }
        joinProgress(st, phase)
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
            if (phase == Phase.IDLE && old != Phase.IDLE && !_ui.value.joining) clearUi()
        }
    }
}
