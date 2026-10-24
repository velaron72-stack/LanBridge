package app.lanbridge.ui

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.lanbridge.core.Mode
import app.lanbridge.core.Phase
import app.lanbridge.core.TunnelController
import app.lanbridge.core.UiState
import app.lanbridge.core.WinTun
import app.lanbridge.vpn.TunnelVpnService
import kotlinx.coroutines.delay

private enum class Sheet { NONE, HELP, SETTINGS, LOG, QR }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen() {
    val ctx = LocalContext.current
    val ui by TunnelController.ui.collectAsState()
    var sheet by remember { mutableStateOf(Sheet.NONE) }
    var showStartup by rememberSaveable { mutableStateOf(true) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    var groupAutoStarted by rememberSaveable { mutableStateOf(false) }
    val snack = remember { SnackbarHostState() }

    // short messages of the copy/paste/QR actions (the phone shows them as toasts)
    LaunchedEffect(Unit) {
        SysActions.notice.collect { m ->
            if (m != null) {
                SysActions.notice.value = null
                snack.currentSnackbarData?.dismiss()
                snack.showSnackbar(m)
            }
        }
    }

    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            now = System.currentTimeMillis()
        }
    }

    fun startTunnel() {
        ctx.startService(Intent(ctx, TunnelVpnService::class.java).setAction(TunnelVpnService.ACTION_START))
    }

    // There is no VPN consent dialog on a PC: the adapter needs administrator rights, which the app asks for at launch.
    fun askVpn() {
        if (!WinTun.isElevated()) {
            TunnelController.reportError("Нужны права администратора. Закройте LanBridge и запустите заново, подтвердив запрос Windows (UAC)")
            if (TunnelController.ui.value.joining) TunnelController.resetAll()
            return
        }
        startTunnel()
    }

    fun onCreateCode() {
        TunnelController.createCode()
    }

    fun onConnect() {
        val err = TunnelController.prepareConnect()
        if (err != null) {
            TunnelController.reportError(err)
            return
        }
        askVpn()
    }

    fun onCreateGroup() {
        TunnelController.createGroup()
    }

    fun onJoinGroup() {
        TunnelController.joinGroup()
    }

    fun onStartGroup() {
        val err = TunnelController.prepareStartGroup()
        if (err != null) {
            TunnelController.reportError(err)
            return
        }
        askVpn()
    }

    // A PC has no camera scanner: the QR code is read from a picture (a screenshot or a saved image) or from the clipboard.
    fun onScan() {
        val f = SysActions.pickImage("Картинка с QR-кодом")
        if (f != null) {
            val text = QrUtil.decodeFile(f)
            if (text != null) TunnelController.setFriendText(text) else TunnelController.reportError("На картинке не найден QR-код")
        }
    }

    // The creator of a group needs no extra tap: as soon as the code exists, the tunnel is started.
    // If that fails, the "Запустить" button is still there.
    LaunchedEffect(ui.groupRole, ui.phase, ui.myCode != null, ui.busy) {
        if (ui.groupRole == 0) {
            groupAutoStarted = false
        } else if (ui.groupRole == 1 && ui.phase == Phase.READY && ui.myCode != null && !ui.busy && !groupAutoStarted) {
            groupAutoStarted = true
            onStartGroup()
        }
    }

    // A newcomer is admitted and knows the network: start the VPN with the layout the core computed.
    LaunchedEffect(ui.joinReady) {
        if (ui.joinReady) {
            TunnelController.consumeJoinReady()
            askVpn()
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snack) },
        topBar = {
            TopAppBar(
                title = { Text("LanBridge", fontWeight = FontWeight.SemiBold) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                    actionIconContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
                actions = {
                    IconButton(onClick = { sheet = Sheet.LOG }) { Icon(Icons.Filled.Build, contentDescription = "Журнал") }
                    IconButton(onClick = { sheet = Sheet.SETTINGS }) { Icon(Icons.Filled.Settings, contentDescription = "Настройки") }
                    IconButton(onClick = { sheet = Sheet.HELP }) { Icon(Icons.Filled.Info, contentDescription = "Справка") }
                },
            )
        },
    ) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val err = ui.error
            if (err != null) ErrorBanner(err)

            val active = ui.phase == Phase.CONNECTING || ui.phase == Phase.CONNECTED ||
                ui.phase == Phase.STALLED || ui.phase == Phase.FAILED
            if (active) {
                ActiveSection(ui, now, onShowQr = { sheet = Sheet.QR }) { TunnelController.disconnect(ctx) }
            } else {
                if (ui.myCode == null && !ui.joining) {
                    ModeSwitch(ui.mode, enabled = !ui.busy) { TunnelController.setMode(it) }
                }
                if (ui.mode == Mode.GROUP) {
                    GroupSetup(
                        ui = ui,
                        now = now,
                        onCreate = { onCreateGroup() },
                        onShowQr = { sheet = Sheet.QR },
                        onScan = { onScan() },
                        onJoin = { onJoinGroup() },
                        onStart = { onStartGroup() },
                        onClose = { TunnelController.resetAll() },
                    )
                } else {
                    SetupSection(
                        ui = ui,
                        now = now,
                        onCreate = { onCreateCode() },
                        onShowQr = { sheet = Sheet.QR },
                        onScan = { onScan() },
                        onConnect = { onConnect() },
                    )
                }
            }

            Text(
                "LanBridge ${SysActions.versionName(ctx)} для Windows (установлено ${SysActions.installedAt(ctx)}). Туннель работает на уровне IP " +
                    "через адаптер Wintun: пересылаются unicast, broadcast и multicast. Программы, привязанные к " +
                    "одному сетевому адаптеру, и протоколы не поверх IP работать не будут.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp, bottom = 16.dp),
            )
        }
    }

    if (showStartup) {
        StartupDialog(
            onOk = { showStartup = false },
            onSettings = {
                showStartup = false
                sheet = Sheet.SETTINGS
            },
        )
    }

    when (sheet) {
        Sheet.HELP -> HelpDialog { sheet = Sheet.NONE }
        Sheet.SETTINGS -> SettingsDialog { sheet = Sheet.NONE }
        Sheet.LOG -> LogDialog { sheet = Sheet.NONE }
        Sheet.QR -> {
            val code = ui.myCode
            if (code != null) {
                QrDialog(code) { sheet = Sheet.NONE }
            } else {
                LaunchedEffect(Unit) { sheet = Sheet.NONE }
            }
        }
        Sheet.NONE -> {}
    }
}

@Composable
internal fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.SemiBold,
            )
            content()
        }
    }
}

@Composable
internal fun ErrorBanner(msg: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Row(
            Modifier.padding(start = 14.dp, top = 6.dp, bottom = 6.dp, end = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                msg,
                color = MaterialTheme.colorScheme.onErrorContainer,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { TunnelController.clearError() }) { Text("OK") }
        }
    }
}

@Composable
internal fun CodeBox(code: String) {
    Box(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(12.dp),
    ) {
        SelectionContainer {
            Text(code, fontFamily = FontFamily.Monospace, fontSize = 12.sp, lineHeight = 16.sp)
        }
    }
}

@Composable
internal fun Line(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            textAlign = TextAlign.End,
            modifier = Modifier
                .weight(1f)
                .padding(start = 12.dp),
        )
    }
}

@Composable
private fun SetupSection(
    ui: UiState,
    now: Long,
    onCreate: () -> Unit,
    onShowQr: () -> Unit,
    onScan: () -> Unit,
    onConnect: () -> Unit,
) {
    val ctx = LocalContext.current
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val small = MaterialTheme.typography.bodySmall

    SectionCard("1. Ваш код") {
        val code = ui.myCode
        if (code == null) {
            Text(
                "Код содержит ваши сетевые адреса и открытый ключ. Ограничен по времени, секретов в нём нет.",
                style = small,
                color = muted,
            )
            Button(onClick = onCreate, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) {
                Text(if (ui.busy) "Определяю внешний адрес…" else "Создать код")
            }
            if (ui.busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        } else {
            CodeBox(code)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { SysActions.copy(ctx, code) },
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 8.dp),
                ) { Text("Копировать") }
                OutlinedButton(
                    onClick = { SysActions.share(ctx, code) },
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 8.dp),
                ) { Text("Отправить") }
                OutlinedButton(
                    onClick = onShowQr,
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 8.dp),
                ) { Text("QR") }
            }
            val left = Fmt.remaining(ui.myExpiresAt, now)
            Text(
                if (left != null) "Действует ещё $left" else "Код истёк — создайте новый",
                style = small,
                color = if (left != null) muted else MaterialTheme.colorScheme.error,
            )
            Text(
                "Доступен по: ${Fmt.families(ui.myFamilies)}",
                style = small,
                color = if (ui.myFamilies == 3) muted else warnColor(),
            )
            Text(
                "NAT (IPv4): ${Fmt.nat(ui.myNat)}",
                style = small,
                color = if (ui.myNat == 2) warnColor() else muted,
            )
            if (ui.stunAnswered == 0) {
                Text(
                    "STUN-серверы не ответили: в коде только локальные адреса (подходит для одной сети).",
                    style = small,
                    color = warnColor(),
                )
            }
            for (c in ui.myCandidates) {
                Text(Fmt.cand(c), style = small, color = muted, fontFamily = FontFamily.Monospace)
            }
            TextButton(onClick = onCreate, enabled = !ui.busy) { Text("Создать заново") }
        }
    }

    SectionCard("2. Код друга") {
        OutlinedTextField(
            value = ui.friendText,
            onValueChange = { TunnelController.setFriendText(it) },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
            maxLines = 5,
            placeholder = { Text("Вставьте код или всё сообщение с кодом") },
            textStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
            isError = ui.friendError != null,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(
                onClick = { TunnelController.setFriendText(SysActions.paste(ctx)) },
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 8.dp),
            ) { Text("Вставить") }
            OutlinedButton(
                onClick = onScan,
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 8.dp),
            ) { Text("Сканировать QR") }
            if (ui.friendText.isNotEmpty()) {
                TextButton(onClick = { TunnelController.setFriendText("") }) { Text("Очистить") }
            }
        }
        val f = ui.friend
        val fe = ui.friendError
        if (f != null) {
            val left = Fmt.remaining(f.expiresAt, now)
            Text(
                "Код принят: ${f.name.ifBlank { "друг" }} · " + (if (left != null) "ещё $left" else "истёк"),
                style = MaterialTheme.typography.bodyMedium,
                color = if (left != null) okColor() else MaterialTheme.colorScheme.error,
            )
            Text(
                "Друг доступен по: ${Fmt.families(f.families)}",
                style = small,
                color = if (f.families == 3) muted else warnColor(),
            )
            Text(
                "NAT друга (IPv4): ${Fmt.nat(f.nat)}",
                style = small,
                color = if (f.nat == 2) warnColor() else muted,
            )
        } else if (fe != null) {
            Text(fe, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
        }
    }

    val canConnect = ui.phase == Phase.READY && ui.myCode != null && ui.friend != null && !ui.busy
    Button(
        onClick = onConnect,
        enabled = canConnect,
        modifier = Modifier
            .fillMaxWidth()
            .height(52.dp),
    ) { Text("Подключиться", fontWeight = FontWeight.SemiBold) }
    val why = when {
        ui.myCode == null -> "Сначала создайте свой код."
        ui.friend == null -> "Введите код друга."
        else -> "Оба нажимают «Подключиться» с разницей не больше минуты."
    }
    Text(why, style = small, color = muted)
}

@Composable
private fun ActiveSection(ui: UiState, now: Long, onShowQr: () -> Unit, onDisconnect: () -> Unit) {
    val group = ui.groupRole != 0
    if (group) GroupStatusCard(ui) else StatusCard(ui)
    val leave = when (ui.groupRole) {
        1 -> "Закрыть группу"
        2 -> "Выйти"
        else -> "Отключить"
    }
    when (ui.phase) {
        Phase.CONNECTING -> {
            OutlinedButton(onClick = onDisconnect, modifier = Modifier.fillMaxWidth()) { Text(if (group) leave else "Отмена") }
        }
        Phase.CONNECTED, Phase.STALLED -> {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { TunnelController.runLanTest() },
                    enabled = ui.phase == Phase.CONNECTED && !ui.testing && (!group || ui.layout?.peer?.isNotEmpty() == true),
                    modifier = Modifier.weight(1f),
                ) { Text(if (ui.testing) "Проверяю…" else "Проверка LAN") }
                OutlinedButton(onClick = onDisconnect, modifier = Modifier.weight(1f)) { Text(leave) }
            }
        }
        Phase.FAILED -> {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { TunnelController.retry() }, modifier = Modifier.weight(1f)) { Text("Повторить") }
                OutlinedButton(onClick = onDisconnect, modifier = Modifier.weight(1f)) { Text(leave) }
            }
        }
        else -> {}
    }
    val r = ui.testResult
    if (r != null) {
        SectionCard("Проверка LAN") {
            SelectionContainer {
                Text(r.substringAfter('\n', r), fontFamily = FontFamily.Monospace, fontSize = 12.sp, lineHeight = 17.sp)
            }
        }
    }
    if (group) {
        MembersCard(ui, "Участники")
        if (ui.groupRole == 1 && ui.myCode != null) GroupCodeCard(ui, now, onShowQr)
    }
}

@Composable
private fun StatusCard(ui: UiState) {
    val s = ui.stats
    val (title, color) = when (ui.phase) {
        Phase.CONNECTING -> "Соединяюсь…" to warnColor()
        Phase.CONNECTED -> "Подключено" to okColor()
        Phase.STALLED -> (if (s != null && s.peerLeft) "Друг отключился" else "Нет ответа от друга") to warnColor()
        Phase.FAILED -> "Не удалось подключиться" to MaterialTheme.colorScheme.error
        else -> "" to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, style = MaterialTheme.typography.headlineSmall, color = color, fontWeight = FontWeight.SemiBold)
            if (ui.phase == Phase.CONNECTING) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            val fm = ui.members.firstOrNull()
            val name = fm?.name?.ifBlank { null } ?: ui.friend?.name?.ifBlank { null }
            if (name != null || fm != null) {
                PersonRow(
                    name = name ?: "Друг",
                    avatar = if (fm != null) ui.avatars[fm.slot] else null,
                    line = "друг",
                    extra = "",
                    dot = color,
                )
            }
            val l = ui.layout
            if (l != null) {
                Line("Ваш адрес", l.my)
                Line("Адрес друга", l.peer)
                Line("Сеть", "${l.net}/${l.prefix}")
                if (l.realMine.isNotEmpty()) Line("Ваш реальный адрес", l.realMine.joinToString())
                if (l.aliasRoutes.isNotEmpty()) Line("Реальный адрес друга", l.aliasRoutes.joinToString())
                if (l.my6.isNotEmpty()) {
                    Line("IPv6: ваш адрес", l.my6)
                    Line("IPv6: адрес друга", l.peer6)
                    if (l.realMine6.isNotEmpty()) Line("IPv6: ваш реальный", l.realMine6.joinToString())
                    if (l.aliasRoutes6.isNotEmpty()) Line("IPv6: реальный друга", l.aliasRoutes6.joinToString())
                }
            }
            if (s != null && (ui.phase == Phase.CONNECTED || ui.phase == Phase.STALLED)) {
                val path = when (s.pathLocal) {
                    1 -> "напрямую, локальная сеть"
                    0 -> "напрямую через интернет"
                    else -> "—"
                }
                val fam = if (ui.pathText.startsWith("[")) "IPv6" else "IPv4"
                Line("Путь", if (ui.pathText.isNotEmpty()) "$path, $fam (${ui.pathText})" else path)
                Line("Задержка", if (s.rttMs >= 0) "${s.rttMs} мс" else "измеряется…")
                Line("В сети", Fmt.duration(s.connectedSec))
                Line("Трафик", "↓ ${Fmt.bytes(s.rxBytes)} · ↑ ${Fmt.bytes(s.txBytes)}")
                Line("Broadcast", "↑ ${s.bcastTx} · ↓ ${s.bcastRx}")
                Line("Multicast", "↑ ${s.mcastTx} · ↓ ${s.mcastRx}")
                if (s.dropped > 0) Line("Отброшено пакетов", "${s.dropped}")
            }
            val hint = ui.hint
            if (hint != null) {
                Text(hint, style = MaterialTheme.typography.bodyMedium, color = warnColor())
            }
        }
    }
}
