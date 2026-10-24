package app.lanbridge.core

import java.io.File

/**
 * The virtual network adapter of the PC build (Wintun) and a few Windows services, implemented in lanbridge.dll
 * (wintun_win.cpp). Text crosses the boundary as Java strings; the adapter's packets never reach Java: the core
 * reads and writes them through the fd that [open] returns.
 */
object WinTun {
    init {
        NativeLib.load()
    }

    const val ADAPTER_NAME = "LanBridge"

    /** Fixed identity of the adapter: Windows keeps its network profile and settings between runs. */
    const val ADAPTER_GUID = "{7A1B8E3C-5D44-4F0B-9C21-6E0A5B7D2F11}"

    external fun load(dllPath: String): String
    external fun open(name: String, guid: String): Int
    external fun swapPair(): Int
    /**
     * Addresses, MTU and metric of the adapter, and host routes to the real addresses of the other devices
     * ([alias4] and [alias6]: comma separated lists). The answer holds lines "E:…", "W:…" and "I:…".
     */
    external fun configure(ip4: String, prefix4: Int, ip6: String, prefix6: Int, mtu: Int, metric: Int, alias4: String, alias6: String): String
    external fun close()
    external fun error(): String
    external fun stats(): String
    external fun isElevated(): Boolean
    external fun relaunchElevated(exe: String, args: String): Boolean
    external fun run(cmd: String, timeoutMs: Int): String
    external fun keepAwake(on: Boolean)

    /** Loads wintun.dll from the folder of lanbridge.dll. Returns an error text or null. */
    fun loadDriverLibrary(): String? {
        val d = NativeLib.dir ?: return "папка приложения не определена"
        val f = File(d, "wintun.dll")
        if (!f.isFile) return "wintun.dll не найден (${f.path})"
        val e = load(f.absolutePath)
        return e.ifEmpty { null }
    }

    /** Runs a program without a window: the exit code and what it printed. */
    fun exec(cmd: String, timeoutMs: Int = 15000): Pair<Int, String> {
        val r = run(cmd, timeoutMs)
        val nl = r.indexOf('\n')
        val code = (if (nl < 0) r else r.substring(0, nl)).trim().toIntOrNull() ?: -1
        return code to (if (nl < 0) "" else r.substring(nl + 1))
    }

    /** %SystemRoot%\System32\<name>: system tools are called by full path, never through PATH. */
    fun system32(name: String): String {
        val root = System.getenv("SystemRoot") ?: "C:\\Windows"
        return "$root\\System32\\$name"
    }
}
