package app.lanbridge

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.res.loadImageBitmap
import androidx.compose.ui.res.useResource
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import app.lanbridge.core.Native
import app.lanbridge.core.NativeLib
import app.lanbridge.core.TunnelController
import app.lanbridge.core.WinTun
import app.lanbridge.ui.LanBridgeTheme
import app.lanbridge.ui.MainScreen
import app.lanbridge.vpn.TunnelVpnService
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileLock
import kotlin.system.exitProcess

private var instanceLock: FileLock? = null

/** Quotes one command-line argument for CreateProcess/ShellExecute. */
private fun quoteArg(a: String): String = if (a.isEmpty() || a.any { it == ' ' || it == '\t' || it == '"' }) "\"" + a.replace("\"", "\\\"") + "\"" else a

/**
 * Before any window: loads lanbridge.dll, gets administrator rights (Wintun needs them to create the adapter: the app
 * starts itself again through the UAC prompt and exits), and makes sure only one copy runs.
 * Returns the text of a problem that stops the app, or null.
 */
private fun boot(args: Array<String>): String? {
    try {
        NativeLib.load()
    } catch (t: Throwable) {
        return "Не удалось загрузить lanbridge.dll: ${t.message}"
    }
    val exe = ProcessHandle.current().info().command().orElse(null)
    val exeName = exe?.substringAfterLast('\\')?.lowercase() ?: ""
    if (!WinTun.isElevated() && !args.contains("--no-elevate") && exe != null && exeName != "java.exe" && exeName != "javaw.exe") {
        if (WinTun.relaunchElevated(exe, args.joinToString(" ") { quoteArg(it) })) exitProcess(0)
        // the prompt was declined: the app opens anyway, starting the tunnel will say what is missing
    }
    try {
        val dir = SharedPreferences.dataDir()
        dir.mkdirs()
        val ch = RandomAccessFile(File(dir, "instance.lock"), "rw").channel
        val lock = ch.tryLock()
        if (lock == null) return "LanBridge уже запущен. Закройте другое окно LanBridge."
        instanceLock = lock
    } catch (_: Exception) {
        // no lock file: not worth stopping for
    }
    return null
}

/**
 * Smoke test of the packaged app, used by CI on a real Windows: --check loads lanbridge.dll and wintun.dll and calls the
 * engine; --check-adapter also creates, configures and removes the Wintun adapter (needs administrator rights).
 * --check-out <file> gets a copy of the report (a windowed app has no console). Exit code 0 means all went well.
 */
private fun selfCheck(args: Array<String>): Int {
    val sb = StringBuilder()
    fun say(m: String) {
        sb.append(m).append('\n')
        println(m)
    }
    var code = 0
    try {
        NativeLib.load()
        say("lanbridge.dll: ${NativeLib.dir}")
        say("elevated: ${WinTun.isElevated()}")
        val e = WinTun.loadDriverLibrary()
        if (e != null) {
            say("wintun.dll: FAIL $e")
            code = 2
        } else {
            say("wintun.dll: ok")
        }
        say("engine status fields: ${Native.status()?.size}")
        if (code == 0 && args.contains("--check-adapter")) {
            val fd = WinTun.open(WinTun.ADAPTER_NAME, WinTun.ADAPTER_GUID)
            if (fd < 0) {
                say("adapter: FAIL ${WinTun.error()}")
                code = 3
            } else {
                say("adapter: ok, fd=$fd")
                val r = WinTun.configure("10.77.9.2", 24, "fd77:9::2", 64, 1500, 1, "192.0.2.77", "")
                say("configure: ${r.trim()}")
                if (r.lineSequence().any { it.startsWith("E:") }) code = 3
                say("stats: ${WinTun.stats()}")
                WinTun.close()
            }
        }
    } catch (t: Throwable) {
        say("FAIL: $t")
        code = 1
    }
    say("result: $code")
    val i = args.indexOf("--check-out")
    if (i >= 0 && i + 1 < args.size) {
        try {
            File(args[i + 1]).writeText(sb.toString())
        } catch (_: Exception) {
        }
    }
    return code
}

fun main(args: Array<String>) {
    if (args.contains("--check")) exitProcess(selfCheck(args))
    val problem = boot(args)
    if (problem == null) {
        TunnelController.init(Context())
        TunnelVpnService.recoverFirewall()
        Runtime.getRuntime().addShutdownHook(Thread({ TunnelVpnService.shutdownBlocking() }, "lanbridge-exit"))
    }
    val icon = try {
        BitmapPainter(useResource("icon.png", ::loadImageBitmap))
    } catch (_: Throwable) {
        null
    }
    application {
        if (problem != null) {
            Window(
                onCloseRequest = ::exitApplication,
                title = "LanBridge",
                icon = icon,
                state = rememberWindowState(size = DpSize(520.dp, 260.dp)),
            ) {
                LanBridgeTheme {
                    Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).padding(20.dp)) {
                        Column(verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(16.dp)) {
                            Text(problem, color = MaterialTheme.colorScheme.error)
                            Button(onClick = ::exitApplication) { Text("Закрыть") }
                        }
                    }
                }
            }
        } else {
            val ui by TunnelController.ui.collectAsState()
            val status = TunnelVpnService.statusText(ui)
            Window(
                onCloseRequest = {
                    TunnelVpnService.shutdownBlocking()
                    exitApplication()
                },
                title = if (status.isEmpty()) "LanBridge" else "LanBridge — $status",
                icon = icon,
                state = rememberWindowState(size = DpSize(540.dp, 900.dp)),
            ) {
                window.minimumSize = java.awt.Dimension(420, 560)
                LanBridgeTheme {
                    Box(
                        Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background),
                        contentAlignment = Alignment.TopCenter,
                    ) {
                        Box(Modifier.widthIn(max = 720.dp).fillMaxHeight()) { MainScreen() }
                    }
                }
            }
        }
    }
}
