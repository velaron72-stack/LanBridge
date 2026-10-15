package app.lanbridge.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.lanbridge.core.Member
import app.lanbridge.core.Mode
import app.lanbridge.core.Phase
import app.lanbridge.core.TunnelController
import app.lanbridge.core.UiState

// ---------------------------------------------------------------------------------------------- mode switch

/** "Группа" / "Вдвоём". Switching is possible while this device has no code of its own and nothing is running. */
@Composable
internal fun ModeSwitch(mode: Mode, enabled: Boolean, onChange: (Mode) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        for ((m, label) in listOf(Mode.GROUP to "Группа", Mode.DIRECT to "Вдвоём")) {
            if (m == mode) {
                Button(onClick = {}, modifier = Modifier.weight(1f)) { Text(label) }
            } else {
                OutlinedButton(onClick = { onChange(m) }, enabled = enabled, modifier = Modifier.weight(1f)) { Text(label) }
            }
        }
    }
    Text(
        if (mode == Mode.GROUP) {
            "До 8 устройств в одной сети. Создатель отправляет всем один код, остальные только вставляют его и нажимают «Подключиться»."
        } else {
            "Два устройства. Оба создают код, обмениваются кодами и нажимают «Подключиться»."
        },
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

// ---------------------------------------------------------------------------------------------- setup (group)

@Composable
internal fun GroupSetup(
    ui: UiState,
    now: Long,
    onCreate: () -> Unit,
    onShowQr: () -> Unit,
    onScan: () -> Unit,
    onJoin: () -> Unit,
    onStart: () -> Unit,
    onClose: () -> Unit,
) {
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val small = MaterialTheme.typography.bodySmall
    if (ui.groupRole == 1 && ui.myCode != null) {
        GroupCodeCard(ui, now, onShowQr)
        MembersCard(ui, "Участники")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onStart, enabled = !ui.busy, modifier = Modifier.weight(1f)) { Text("Запустить") }
            OutlinedButton(onClick = onClose, modifier = Modifier.weight(1f)) { Text("Закрыть группу") }
        }
        Text(
            "Туннель запускается сам. Если система спросила разрешение на VPN и вы отказали, нажмите «Запустить».",
            style = small,
            color = muted,
        )
    } else if (ui.joining) {
        JoinProgressCard(ui, now)
    } else {
        CreateGroupCard(ui, onCreate)
        JoinGroupCard(ui, now, onScan, onJoin)
    }
}

@Composable
private fun CreateGroupCard(ui: UiState, onCreate: () -> Unit) {
    SectionCard("Создать группу") {
        Text(
            "Вы получаете код группы и отправляете его остальным (до 7 человек). Им ничего отправлять в ответ не нужно. " +
                "Код действует ограниченное время и подходит всем, кто вставит его, пока он не истёк.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(onClick = onCreate, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) {
            Text(if (ui.busy && !ui.joining) "Определяю внешний адрес…" else "Создать группу")
        }
        if (ui.busy && !ui.joining) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun JoinGroupCard(ui: UiState, now: Long, onScan: () -> Unit, onJoin: () -> Unit) {
    val ctx = LocalContext.current
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val small = MaterialTheme.typography.bodySmall
    SectionCard("Войти в группу") {
        OutlinedTextField(
            value = ui.friendText,
            onValueChange = { TunnelController.setFriendText(it) },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
            maxLines = 5,
            placeholder = { Text("Вставьте код группы или всё сообщение с кодом") },
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
        var ready = false
        if (f != null && f.isGroup) {
            val left = Fmt.remaining(f.expiresAt, now)
            ready = left != null
            Text(
                "Группа найдена: ${f.name.ifBlank { "создатель" }} · " + (if (left != null) "код действует ещё $left" else "код истёк"),
                style = MaterialTheme.typography.bodyMedium,
                color = if (left != null) okColor() else MaterialTheme.colorScheme.error,
            )
            if (f.maxMembers > 0) Text("Размер группы: до ${f.maxMembers} устройств", style = small, color = muted)
            Text(
                "Создатель доступен по: ${Fmt.families(f.families)}",
                style = small,
                color = if (f.families == 3) muted else warnColor(),
            )
        } else if (fe != null) {
            Text(fe, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
        }
        Button(
            onClick = onJoin,
            enabled = ready && !ui.busy,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) { Text("Подключиться", fontWeight = FontWeight.SemiBold) }
        Text(
            if (f == null) "Вставьте код группы, который прислал создатель." else "Больше ничего не нужно: создатель увидит вас сам.",
            style = small,
            color = muted,
        )
    }
}

@Composable
private fun JoinProgressCard(ui: UiState, now: Long) {
    val started = remember { System.currentTimeMillis() }
    val waited = (now - started) / 1000
    SectionCard("Вход в группу") {
        val creator = ui.friend?.name?.ifBlank { null }
        Text(
            when (ui.joinState) {
                2 -> "Вас приняли${if (creator != null) " ($creator)" else ""}. Получаю список участников и поднимаю сеть…"
                else -> "Стучусь к создателю${if (creator != null) " ($creator)" else ""}…"
            },
            style = MaterialTheme.typography.bodyMedium,
        )
        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        if (ui.joinState != 2 && waited >= 12) {
            Text(
                "Создатель пока не отвечает. Он должен создать группу и не закрывать приложение, код не должен истечь, " +
                    "у всех должна быть одна сборка. При строгом NAT помогает IPv6 у обоих или один общий Wi-Fi.",
                style = MaterialTheme.typography.bodySmall,
                color = warnColor(),
            )
        }
        OutlinedButton(onClick = { TunnelController.resetAll() }, modifier = Modifier.fillMaxWidth()) { Text("Отмена") }
    }
}

// ---------------------------------------------------------------------------------------------- creator: the code

/** The group code of the creator: copy, send, QR, time left and a new code for the same group. */
@Composable
internal fun GroupCodeCard(ui: UiState, now: Long, onShowQr: () -> Unit) {
    val ctx = LocalContext.current
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val small = MaterialTheme.typography.bodySmall
    val code = ui.myCode ?: return
    SectionCard("Код группы") {
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
            if (left != null) "Действует ещё $left. Им могут воспользоваться несколько человек." else "Код истёк: новые участники не войдут. Нажмите «Продлить».",
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
        TextButton(onClick = { TunnelController.renewGroup() }) { Text("Продлить код") }
    }
}

// ---------------------------------------------------------------------------------------------- members

@Composable
private fun StateDot(color: Color) {
    Box(
        Modifier
            .size(10.dp)
            .clip(CircleShape)
            .background(color),
    )
}

@Composable
internal fun PersonRow(name: String, avatar: ByteArray?, line: String, extra: String, dot: Color) {
    Row(
        Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        AvatarView(name, avatar, 44.dp)
        Column(Modifier.weight(1f)) {
            Text(name, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
            if (line.isNotEmpty()) {
                Text(line, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (extra.isNotEmpty()) {
                Text(
                    extra,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
        StateDot(dot)
    }
}

@Composable
private fun memberDot(m: Member): Color = when (m.state) {
    2 -> okColor()
    1, 3 -> warnColor()
    else -> MaterialTheme.colorScheme.outline
}

/** This device first, then the others in the order of their slots, each with the avatar and the state of the link. */
@Composable
internal fun MembersCard(ui: UiState, title: String) {
    val small = MaterialTheme.typography.bodySmall
    SectionCard(title) {
        val me = ui.myProfileName.ifBlank { "Вы" }
        PersonRow(
            name = "$me (вы)",
            avatar = ui.myAvatar,
            line = if (ui.groupRole == 1) "создатель группы" else "участник",
            extra = ui.layout?.my ?: "",
            dot = okColor(),
        )
        for (m in ui.members) {
            val nm = Fmt.memberName(m)
            PersonRow(
                name = if (m.isCreator) "$nm · создатель" else nm,
                avatar = ui.avatars[m.slot],
                line = Fmt.memberLine(m),
                extra = m.ip4,
                dot = memberDot(m),
            )
        }
        if (ui.members.isEmpty()) {
            Text(
                if (ui.groupRole == 1) "Пока никого. Отправьте код группы друзьям." else "Список участников ещё не получен.",
                style = small,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ---------------------------------------------------------------------------------------------- running group

@Composable
internal fun GroupStatusCard(ui: UiState) {
    val s = ui.stats
    val creator = ui.groupRole == 1
    val (title, color) = when (ui.phase) {
        Phase.CONNECTING -> (if (creator && ui.membersKnown == 0) "Группа открыта · ждём участников" else "Соединяюсь с участниками…") to warnColor()
        Phase.CONNECTED -> "Группа подключена" to okColor()
        Phase.STALLED -> "Нет связи с участниками" to warnColor()
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
            if (ui.phase == Phase.CONNECTING && !(creator && ui.membersKnown == 0)) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            Line("Участники", "${ui.membersUp} из ${ui.membersKnown} в сети")
            Line("Группа", "до ${ui.groupMax} устройств")
            val l = ui.layout
            if (l != null) {
                Line("Ваш адрес", l.my)
                Line("Сеть", "${l.net}/${l.prefix}")
                if (l.my6.isNotEmpty()) Line("IPv6: ваш адрес", l.my6)
            }
            if (s != null && (ui.phase == Phase.CONNECTED || ui.phase == Phase.STALLED)) {
                Line("В сети", Fmt.duration(s.connectedSec))
                Line("Трафик", "↓ ${Fmt.bytes(s.rxBytes)} · ↑ ${Fmt.bytes(s.txBytes)}")
                Line("Broadcast", "↑ ${s.bcastTx} · ↓ ${s.bcastRx}")
                Line("Multicast", "↑ ${s.mcastTx} · ↓ ${s.mcastRx}")
                if (s.relayed > 0) Line("Через создателя", "${s.relayed} пакетов")
                if (s.dropped > 0) Line("Отброшено пакетов", "${s.dropped}")
            }
            val hint = ui.hint
            if (hint != null) {
                Text(hint, style = MaterialTheme.typography.bodyMedium, color = warnColor())
            }
        }
    }
}
