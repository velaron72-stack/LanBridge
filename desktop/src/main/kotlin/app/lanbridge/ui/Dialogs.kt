package app.lanbridge.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.lanbridge.core.AvatarUtil
import app.lanbridge.core.Native
import app.lanbridge.core.Prefs
import app.lanbridge.core.TunnelController
import app.lanbridge.vpn.TunnelVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val HELP_TEXT =
    "Группа (2–8 устройств)\n" +
        "1. Создатель нажимает «Создать группу»: появляется код группы, туннель запускается сам.\n" +
        "2. Создатель отправляет код остальным (копировать, «Отправить» или QR).\n" +
        "3. Остальные вставляют этот код (или сканируют QR) и нажимают «Подключиться». Больше ничего " +
        "отправлять не нужно: создатель увидит новичка сам, в списке участников появятся имена и аватарки.\n" +
        "4. Когда статус «Группа подключена», запускайте игру: все видят друг друга как устройства в одной локальной сети.\n" +
        "• Код подходит всем, кто вставит его, пока он не истёк (срок задаётся в настройках). «Продлить код» даёт " +
        "новый код для той же группы, участники при этом не отключаются.\n" +
        "• Состав группы: до 8 устройств. Каждый подключается к каждому напрямую; если прямой путь между двумя " +
        "участниками не получился, пакеты идут через создателя (в списке видно «через создателя группы»).\n" +
        "• Если создатель вышел, остальные продолжают общаться напрямую. Не работают только связи, шедшие через " +
        "создателя, и вход новых участников.\n\n" +
        "Вдвоём (прямое соединение)\n" +
        "1. Оба нажимают «Создать код».\n" +
        "2. Отправьте свой код другу (мессенджер или QR), вставьте его код.\n" +
        "3. Оба нажимают «Подключиться» с разницей не больше минуты.\n" +
        "4. Когда статус «Подключено», запускайте игру: друг виден как устройство в локальной сети.\n\n" +
        "Имя и аватарка\n" +
        "Задаются в настройках. Их видят остальные участники в списке участников. Фото " +
        "сжимается до 128×128 и передаётся по зашифрованному туннелю.\n\n" +
        "Как это устроено\n" +
        "Создаётся виртуальная сеть 192.168.x.0/24 (в группе: адреса .1–.8 по порядку входа, у создателя .1), а рядом с " +
        "ней, одновременно, IPv6-сеть fdXX:XXXX:XXXX::/64. Адрес сети считается из секрета группы, поэтому у всех " +
        "одинаковый. На ПК создаётся адаптер «LanBridge» (драйвер Wintun) с этими адресами. Телефоны " +
        "дополнительно зеркалируют реальные адреса устройств, в том числе вашего ПК; на самом ПК реальные " +
        "адреса других участников не зеркалируются: подключайтесь к ним по виртуальным адресам из списка " +
        "участников. Link-local адреса (fe80::) и multicast IPv6 тоже ходят через туннель. Адреса, открытые ключи и " +
        "тип NAT передаются в коде, своего сервера нет (STUN нужен только чтобы узнать внешний адрес). Соединение " +
        "прямое (UDP hole punching), трафик шифруется: X25519, ChaCha20-Poly1305. Broadcast и multicast " +
        "пересылаются всем участникам, поэтому игры, ищущие друг друга по LAN, видят всех.\n\n" +
        "Если не соединяется\n" +
        "• Коды живут ограниченное время: создайте заново или нажмите «Продлить код».\n" +
        "• У всех должна быть одна и та же сборка (номер в заголовке справки): формат кода изменился " +
        "в сборке 20005 (группы), коды старых сборок не принимаются.\n" +
        "• Если NAT (IPv4) симметричный у обоих, а IPv6 нет хотя бы у одного, прямое соединение невозможно: " +
        "подключитесь к одному Wi-Fi или раздайте точку доступа. В группе в таком случае пакеты может " +
        "пересылать создатель, если у него с обоими есть связь.\n" +
        "• Вход в группу при строгом NAT создателя: включите в настройках «Помощь при строгом NAT». Тогда новичок " +
        "оставляет на публичной доске ntfy.sh зашифрованную записку со своими адресами, создатель её читает " +
        "и сам пробивает путь навстречу. Если в сети создателя пробивка проходит и без этого, записка не нужна.\n" +
        "• Другие виртуальные сети (Radmin VPN, Hamachi, ZeroTier) мешать не должны, но игра может искать " +
        "сервер не в той сети: на время игры их лучше отключить.\n" +
        "• Программа должна работать от имени администратора (запрос Windows при запуске): без этого адаптер " +
        "не создаётся.\n" +
        "• Брандмауэр Windows: программа сама добавляет правила для виртуальной сети, включает weak host на " +
        "адаптере и делает сеть адаптера частной. Если игра всё равно не видит друга, включите в настройках " +
        "«Отключать брандмауэр Windows, пока туннель открыт»: брандмауэр выключается при подключении и " +
        "возвращается при отключении или закрытии окна. Если программа была убита и не запускалась снова, " +
        "брандмауэр вернётся при следующем запуске LanBridge (или включите его вручную в «Безопасность Windows»). " +
        "Антивирус Windows и сторонние брандмауэры и антивирусы программа не трогает; если игру блокирует " +
        "сторонний антивирус, отключите его сами.\n\n" +
        "Если игра не стартует\n" +
        "На всех устройствах откройте «Журнал и потоки» (значок с ключом) и нажмите «Сбросить потоки». " +
        "Запустите игру, дождитесь зависания и снова откройте «Журнал и потоки» → «Копировать». Там видно, " +
        "какой трафик игры проходит через туннель: порты, размеры пакетов, первые и последние пакеты. " +
        "Не нажимайте «Проверка LAN» до копирования: она добавляет свой трафик. " +
        "«Проверка LAN» проверяет unicast, broadcast, multicast, большие UDP-пакеты и TCP с первым " +
        "другим участником сети.\n\n" +
        "Ограничения\n" +
        "• Туннель на уровне IP (IPv4 и IPv6). Игры, привязанные к одному сетевому адаптеру или использующие " +
        "не-IP протоколы, не заработают.\n" +
        "• Сам туннель между устройствами идёт по UDP поверх IPv4 и IPv6 одновременно: код содержит адреса обоих " +
        "семейств, соединение устанавливается по тому, что ответит первым, и переключается на другое, если " +
        "путь оборвался. Нужен хотя бы один общий протокол: IPv4-only и IPv6-only устройства друг друга не увидят.\n" +
        "• На ПК нет камеры-сканера: «Сканировать QR» читает QR-код из картинки (скриншот), «Вставить» " +
        "умеет брать код и из картинки в буфере обмена.\n" +
        "• MTU 1500: пакеты больше 1339 байт туннель режет на части сам и собирает у получателя, сеть ничего не " +
        "фрагментирует. Значение MTU лучше держать одинаковым у всех.\n\n" +
        "Работа на ПК\n" +
        "Окно можно свернуть: туннель работает, пока программа запущена. Закрытие окна отключает туннель и " +
        "удаляет адаптер. Пока туннель открыт, компьютер не уходит в сон (можно выключить в настройках)."

/**
 * The question about Windows Firewall, asked once (the answer is kept in the settings). "No" is the default
 * choice: closing the window by Esc or a click outside does not answer.
 */
@Composable
fun FirewallDialog(onAnswer: (Boolean) -> Unit) {
    AlertDialog(
        onDismissRequest = {},
        title = { Text("Отключить брандмауэр Windows?") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Брандмауэр Windows часто не пускает игры через виртуальную сеть. LanBridge может сам " +
                        "выключить его, пока туннель открыт, и включить обратно при отключении или закрытии окна.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    "Да: брандмауэр выключается на время работы туннеля, все три профиля (доменный, частный, " +
                        "общедоступный). До этого его состояние сохраняется и потом восстанавливается.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    "Нет: ничего не меняется. Программа только добавляет разрешающие правила для своей сети.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    "Пока брандмауэр выключен, компьютер не защищён от входящих подключений из сети. Если " +
                        "программу убить и больше не запускать, брандмауэр останется выключенным до следующего запуска " +
                        "LanBridge: тогда он включится сам, или включите его вручную. Антивирус Windows и сторонние " +
                        "программы защиты не затрагиваются. Выбор можно изменить в настройках.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = { TextButton(onClick = { onAnswer(false) }) { Text("Нет") } },
        dismissButton = { TextButton(onClick = { onAnswer(true) }) { Text("Да, отключать") } },
    )
}

/** Shown on every launch of the app. */
@Composable
fun StartupDialog(onOk: () -> Unit, onSettings: () -> Unit) {
    AlertDialog(
        onDismissRequest = onOk,
        title = { Text("Приложение в разработке") },
        text = {
            Text(
                "LanBridge проходит тестирование. Возможны сбои и неполная совместимость с играми.\n\n" +
                    "Программа работает от имени администратора: так Windows разрешает создать сетевой адаптер. " +
                    "Пока окно открыто, туннель и адаптер живы; закройте окно, чтобы отключиться.",
                style = MaterialTheme.typography.bodyMedium,
            )
        },
        confirmButton = { TextButton(onClick = onOk) { Text("ОК") } },
        dismissButton = { TextButton(onClick = onSettings) { Text("Настройки") } },
    )
}

@Composable
fun HelpDialog(onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Закрыть") } },
        title = { Text("Справка · ${SysActions.versionLabel(ctx)}") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(HELP_TEXT, style = MaterialTheme.typography.bodyMedium)
            }
        },
    )
}

@Composable
fun SettingsDialog(onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefs = remember { Prefs(ctx) }
    var name by remember { mutableStateOf(prefs.deviceName) }
    var avatar by remember { mutableStateOf(prefs.avatar) }
    var avatarError by remember { mutableStateOf<String?>(null) }
    var stun by remember { mutableStateOf(prefs.stunServers) }
    var mtu by remember { mutableStateOf(prefs.mtu.toString()) }
    var ttl by remember { mutableStateOf(prefs.ttlMin.toString()) }
    var awake by remember { mutableStateOf(prefs.keepAwake) }
    var hint by remember { mutableStateOf(prefs.hintMailbox) }
    val firewallWas = remember { prefs.firewallMode == Prefs.FIREWALL_OFF }
    var firewall by remember { mutableStateOf(firewallWas) }

    fun pickAvatar() {
        val f = SysActions.pickImage("Фото для аватара") ?: return
        scope.launch {
            val bytes = withContext(Dispatchers.IO) { AvatarUtil.fromFile(f) }
            if (bytes != null) {
                avatar = bytes
                avatarError = null
            } else {
                avatarError = "Не удалось прочитать картинку"
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
        confirmButton = {
            TextButton(onClick = {
                prefs.deviceName = name
                prefs.avatar = avatar
                prefs.stunServers = stun
                prefs.mtu = mtu.trim().toIntOrNull() ?: Prefs.DEFAULT_MTU
                prefs.ttlMin = ttl.trim().toIntOrNull() ?: 10
                prefs.keepAwake = awake
                prefs.hintMailbox = hint
                if (firewall != firewallWas) {
                    prefs.firewallMode = if (firewall) Prefs.FIREWALL_OFF else Prefs.FIREWALL_KEEP
                    // applied at once when the tunnel is open
                    TunnelVpnService.applyFirewallChoice()
                }
                // the name and the avatar go to the other participants right away, also while connected
                TunnelController.applyProfile()
                onDismiss()
            }) { Text("Сохранить") }
        },
        title = { Text("Настройки") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    "Профиль",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.SemiBold,
                )
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                    AvatarView(name.ifBlank { prefs.deviceName }, avatar, 72.dp)
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        OutlinedButton(onClick = { pickAvatar() }) { Text("Выбрать фото") }
                        TextButton(onClick = { avatar = ByteArray(0) }, enabled = avatar.isNotEmpty()) { Text("Убрать") }
                    }
                }
                val ae = avatarError
                if (ae != null) Text(ae, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it.take(20) },
                    label = { Text("Имя (видно другим участникам)") },
                    supportingText = { Text("До 20 символов") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    "Имя и аватар получают остальные участники сразу после соединения. Фото обрезается до квадрата " +
                        "и сжимается до 128×128 (не больше 12 КБ). Без фото вместо аватара показывается буква имени.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Соединение",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.SemiBold,
                )
                OutlinedTextField(
                    value = stun,
                    onValueChange = { stun = it },
                    label = { Text("STUN-серверы (по одному в строке)") },
                    minLines = 3,
                    maxLines = 6,
                    textStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = mtu,
                    onValueChange = { mtu = it.filter { c -> c.isDigit() }.take(4) },
                    label = { Text("MTU туннеля (1200–1500)") },
                    supportingText = { Text("По умолчанию 1500; у всех устройств одинаковый") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = ttl,
                    onValueChange = { ttl = it.filter { c -> c.isDigit() }.take(2) },
                    label = { Text("Срок действия кода, минут (2–60)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "Не давать компьютеру засыпать, пока туннель открыт",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                    Switch(checked = awake, onCheckedChange = { awake = it })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Отключать брандмауэр Windows, пока туннель открыт", style = MaterialTheme.typography.bodyMedium)
                        Text(
                            "Брандмауэр выключается при подключении и возвращается при отключении или закрытии окна. " +
                                "Нужно, только если игра не видит друга при включённом брандмауэре.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(checked = firewall, onCheckedChange = { firewall = it })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Помощь при строгом NAT (ntfy.sh)", style = MaterialTheme.typography.bodyMedium)
                        Text(
                            "Новичок оставляет на публичной доске ntfy.sh зашифрованную записку со своими сетевыми " +
                                "адресами, создатель группы её читает. Нужно только если вход в группу не проходит напрямую. " +
                                "Расшифровать её может только тот, у кого есть код группы.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(checked = hint, onCheckedChange = { hint = it })
                }
                Text(
                    "Имя и аватар применяются сразу, остальное — при следующем создании кода или подключении. " +
                        "Версия ${SysActions.versionLabel(ctx)}.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}

private fun readDiag(): String = try {
    val flows = Native.text(Native.flows()).trim()
    val log = Native.text(Native.log()).lines().filter { it.isNotBlank() }.asReversed().joinToString("\n")
    "== Трафик через туннель ==\n" +
        (if (flows.isEmpty()) "(пока нет)" else flows) +
        "\n\n== Журнал (новые сверху) ==\n" + log
} catch (_: Throwable) {
    ""
}

@Composable
fun LogDialog(onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    var text by remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        while (true) {
            text = withContext(Dispatchers.IO) { readDiag() }
            delay(1000)
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Закрыть") } },
        dismissButton = {
            Row {
                TextButton(onClick = { Native.resetFlows() }) { Text("Сбросить потоки") }
                TextButton(onClick = { SysActions.copy(ctx, text) }) { Text("Копировать") }
            }
        },
        title = { Text("Журнал и потоки") },
        text = {
            Box(Modifier.heightIn(max = 440.dp)) {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    SelectionContainer {
                        Text(
                            text.ifBlank { "Пусто" },
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            lineHeight = 14.sp,
                        )
                    }
                }
            }
        },
    )
}

@Composable
fun QrDialog(code: String, onDismiss: () -> Unit) {
    val bmp = remember(code) { QrUtil.render(code) }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Закрыть") } },
        title = { Text("QR-код") },
        text = {
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                if (bmp != null) {
                    Image(
                        bitmap = bmp,
                        contentDescription = "QR-код соединения",
                        modifier = Modifier
                            .size(260.dp)
                            .background(Color.White)
                            .padding(6.dp),
                    )
                } else {
                    Text("Не удалось построить QR-код")
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "Телефон сканирует его кнопкой «Сканировать QR».",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
    )
}
