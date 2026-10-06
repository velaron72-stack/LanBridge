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
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import app.lanbridge.core.Native
import app.lanbridge.core.Prefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private const val HELP_TEXT =
    "Как подключиться\n" +
        "1. Оба нажимают «Создать код».\n" +
        "2. Отправьте свой код другу (мессенджер или QR), вставьте его код.\n" +
        "3. Оба нажимают «Подключиться» с разницей не больше минуты.\n" +
        "4. Когда статус «Подключено», запускайте игру: друг виден как устройство в локальной сети.\n\n" +
        "Как это устроено\n" +
        "Создаётся виртуальная сеть 192.168.x.0/24 из двух адресов. Дополнительно туннель зеркалирует реальные " +
        "адреса устройств (например, адрес Wi-Fi): игры, которые привязываются к реальному адресу или сообщают " +
        "его другому игроку, продолжают работать. Адреса, открытые ключи и тип NAT передаются в коде, сервера нет " +
        "(STUN нужен только чтобы узнать внешний адрес). Соединение прямое (UDP hole punching), трафик " +
        "шифруется: X25519, ChaCha20-Poly1305. Broadcast и multicast пересылаются другу, поэтому игры, " +
        "ищущие друг друга по LAN, видят его.\n\n" +
        "Если не соединяется\n" +
        "• Коды живут ограниченное время: создайте заново.\n" +
        "• У обоих должна быть версия 2.0.0 или новее.\n" +
        "• Если NAT симметричный у обоих, прямое соединение невозможно: подключитесь к одному Wi-Fi " +
        "или раздайте точку доступа.\n" +
        "• Отключите другие VPN: Android разрешает только один.\n\n" +
        "Если игра не стартует\n" +
        "На обоих устройствах откройте «Журнал и потоки» (значок с ключом) и нажмите «Сбросить потоки». " +
        "Запустите игру, дождитесь зависания и снова откройте «Журнал и потоки» → «Копировать». Там видно, " +
        "какой трафик игры проходит через туннель: порты, размеры пакетов, первые и последние пакеты. " +
        "Не нажимайте «Проверка LAN» до копирования: она добавляет свой трафик. " +
        "«Проверка LAN» сама проверяет unicast, broadcast, multicast, большие UDP-пакеты и TCP.\n\n" +
        "Ограничения\n" +
        "• Туннель на уровне IPv4 без root. Игры, привязанные к интерфейсу Wi-Fi или использующие не-IP " +
        "протоколы, не заработают.\n\n" +
        "Работа в фоне\n" +
        "Xiaomi, Huawei/Honor, Oppo/Realme, Vivo, Samsung часто закрывают фоновые службы. Разрешите " +
        "автозапуск, снимите ограничение батареи (Настройки → Фоновая работа) и закрепите приложение в " +
        "списке недавних."

/** Shown on every launch of the app. */
@Composable
fun StartupDialog(onOk: () -> Unit, onSettings: () -> Unit) {
    AlertDialog(
        onDismissRequest = onOk,
        title = { Text("Приложение в разработке") },
        text = {
            Text(
                "LanBridge проходит тестирование. Возможны сбои и неполная совместимость с играми.\n\n" +
                    "Чтобы туннель не останавливался в фоне, отключите оптимизацию батареи и разрешите работу " +
                    "в фоновом режиме в настройках.",
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
        title = { Text("Справка · ${SysActions.versionName(ctx)}") },
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
    val prefs = remember { Prefs(ctx) }
    var name by remember { mutableStateOf(prefs.deviceName) }
    var stun by remember { mutableStateOf(prefs.stunServers) }
    var mtu by remember { mutableStateOf(prefs.mtu.toString()) }
    var ttl by remember { mutableStateOf(prefs.ttlMin.toString()) }
    var awake by remember { mutableStateOf(prefs.keepAwake) }

    // The battery state changes in a system screen: re-read it every time the app comes back to the foreground.
    var ignoring by remember { mutableStateOf(SysActions.isIgnoringBatteryOptimizations(ctx)) }
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val obs = LifecycleEventObserver { _, e ->
            if (e == Lifecycle.Event.ON_RESUME) ignoring = SysActions.isIgnoringBatteryOptimizations(ctx)
        }
        owner.lifecycle.addObserver(obs)
        onDispose { owner.lifecycle.removeObserver(obs) }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
        confirmButton = {
            TextButton(onClick = {
                prefs.deviceName = name
                prefs.stunServers = stun
                prefs.mtu = mtu.trim().toIntOrNull() ?: 1280
                prefs.ttlMin = ttl.trim().toIntOrNull() ?: 10
                prefs.keepAwake = awake
                onDismiss()
            }) { Text("Сохранить") }
        },
        title = { Text("Настройки") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    "Фоновая работа",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    if (ignoring) "Оптимизация батареи отключена" else "Оптимизация батареи включена: система может остановить туннель",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (ignoring) okColor() else warnColor(),
                )
                OutlinedButton(
                    onClick = { SysActions.requestIgnoreBatteryOptimizations(ctx) },
                    enabled = !ignoring,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Отключить оптимизацию батареи") }
                OutlinedButton(
                    onClick = { if (!SysActions.openAutostart(ctx)) SysActions.appSettings(ctx) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Разрешить работу в фоне") }
                Text(
                    "Xiaomi, Huawei/Honor, Oppo/Realme, Vivo, Samsung: включите автозапуск, в разделе «Батарея» " +
                        "выберите «Без ограничений» и закрепите приложение в списке недавних.",
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
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Имя устройства (видно другу)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
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
                        "Не засыпать, пока туннель открыт",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                    Switch(checked = awake, onCheckedChange = { awake = it })
                }
                Text(
                    "Изменения применяются при следующем создании кода или подключении. Версия ${SysActions.versionName(ctx)}.",
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
                        bitmap = bmp.asImageBitmap(),
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
                    "Друг сканирует его кнопкой «Сканировать QR».",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
    )
}
