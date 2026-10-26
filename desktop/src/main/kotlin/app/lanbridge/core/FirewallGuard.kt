package app.lanbridge.core

import android.content.SharedPreferences
import java.io.File

/**
 * Switches Windows Firewall off while the tunnel is open, when the user agreed, and puts it back afterwards.
 *
 * Safety first: the firewall is never switched off before its previous state is saved to
 * %APPDATA%\LanBridge\firewall-restore.txt (which profiles were on). The file is removed only after the profiles are
 * confirmed on again, so a crash, a killed process or a power cut leaves everything needed to repair the state:
 * the next start of LanBridge calls [restore]. Nothing else is installed on the computer (no service, no scheduled
 * task): if LanBridge is killed and never started again, the firewall stays off until the user switches it on in
 * Windows, and the question the user answers says so.
 *
 * Only the firewall is touched: Microsoft Defender antivirus, third-party firewalls and antivirus are not.
 * Needs administrator rights (the app has them). Every step is logged to the core journal by the caller.
 */
object FirewallGuard {
    /** The three profiles: key in the saved file, name of the netsh command, key of the registry policy. */
    private class Profile(val key: String, val netsh: String, val regKey: String)

    private val PROFILES = listOf(
        Profile("domain", "domainprofile", "DomainProfile"),
        Profile("private", "privateprofile", "StandardProfile"),
        Profile("public", "publicprofile", "PublicProfile"),
    )

    private const val REG_BASE = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"

    /** Runs a command line without a window: exit code and output. Replaced in tests. */
    @Volatile
    internal var runner: (String, Int) -> Pair<Int, String> = { cmd, timeout -> WinTun.exec(cmd, timeout) }

    /** Where the previous state is kept. Replaced in tests. */
    @Volatile
    internal var stateFile: () -> File = { File(SharedPreferences.dataDir(), "firewall-restore.txt") }

    /** Directory of the system tools; replaced in tests. */
    @Volatile
    internal var system32: (String) -> String = { WinTun.system32(it) }

    private fun netsh() = "\"${system32("netsh.exe")}\""

    private fun ps() = "\"${system32("WindowsPowerShell\\v1.0\\powershell.exe")}\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command"

    /** True while a saved state is waiting to be put back (the firewall may be off because of this app). */
    fun hasPendingRestore(): Boolean = stateFile().isFile

    // ------------------------------------------------------------------ reading the state

    /** Which profiles are on right now, or null when it cannot be read. */
    internal fun readState(): Map<String, Boolean>? {
        // Get-NetFirewallProfile knows the effective setting; "NotConfigured" counts as on (that is the default).
        val (code, out) = runner(
            "${ps()} \"Get-NetFirewallProfile | ForEach-Object { \$_.Name + '=' + [int]([string]\$_.Enabled -ne 'False') }\"",
            25000,
        )
        if (code == 0) parseProfiles(out)?.let { return it }
        // fallback: the registry values the firewall service reads (language independent)
        val res = LinkedHashMap<String, Boolean>()
        var anyRead = false
        for (p in PROFILES) {
            val (c, o) = runner("\"${system32("reg.exe")}\" query \"$REG_BASE\\${p.regKey}\" /v EnableFirewall", 10000)
            val v = if (c == 0) Regex("0x([0-9a-fA-F]+)").find(o)?.groupValues?.get(1)?.toLongOrNull(16) else null
            if (v != null) anyRead = true
            // no value: the default of Windows, the profile is on
            res[p.key] = (v ?: 1L) != 0L
        }
        return if (anyRead) res else null
    }

    /** "Domain=1" lines of the PowerShell output. Null unless all three profiles are present. */
    internal fun parseProfiles(out: String): Map<String, Boolean>? {
        val res = LinkedHashMap<String, Boolean>()
        for (line in out.lineSequence()) {
            val m = Regex("^\\s*(domain|private|public)\\s*=\\s*([01])\\s*$", RegexOption.IGNORE_CASE).find(line) ?: continue
            res[m.groupValues[1].lowercase()] = m.groupValues[2] == "1"
        }
        return if (PROFILES.all { res.containsKey(it.key) }) res else null
    }

    private fun describe(st: Map<String, Boolean>): String =
        PROFILES.joinToString(", ") { "${it.key}=" + (if (st[it.key] == true) "вкл" else "выкл") }

    // ------------------------------------------------------------------ saved state

    private fun writeSaved(st: Map<String, Boolean>) {
        val f = stateFile()
        f.parentFile?.mkdirs()
        val text = "# LanBridge: профили брандмауэра Windows до отключения (1 = были включены)\n" +
            PROFILES.joinToString("\n") { "${it.key}=" + (if (st[it.key] == true) "1" else "0") } + "\n"
        val tmp = File(f.path + ".tmp")
        tmp.writeText(text, Charsets.UTF_8)
        if (!tmp.renameTo(f)) {
            f.writeText(text, Charsets.UTF_8)
            tmp.delete()
        }
    }

    internal fun readSaved(): Map<String, Boolean>? {
        val f = stateFile()
        if (!f.isFile) return null
        return try {
            val res = LinkedHashMap<String, Boolean>()
            for (line in f.readLines(Charsets.UTF_8)) {
                val m = Regex("^(domain|private|public)=([01])$").find(line.trim()) ?: continue
                res[m.groupValues[1]] = m.groupValues[2] == "1"
            }
            // a damaged file: take everything as on, the safe side
            for (p in PROFILES) if (!res.containsKey(p.key)) res[p.key] = true
            res
        } catch (_: Exception) {
            null
        }
    }

    /** The commands that put the saved profiles back: one for all profiles when all were on. */
    internal fun restoreCommands(saved: Map<String, Boolean>): List<String> {
        val on = PROFILES.filter { saved[it.key] == true }
        return when {
            on.isEmpty() -> emptyList()
            on.size == PROFILES.size -> listOf("netsh advfirewall set allprofiles state on")
            else -> on.map { "netsh advfirewall set ${it.netsh} state on" }
        }
    }

    // ------------------------------------------------------------------ switching

    /**
     * Switches all profiles off. Returns one line for the journal. Safe to call again: when the firewall is already
     * off because of an earlier call (the saved state exists), nothing changes.
     */
    @Synchronized
    fun disable(): String {
        val current = readState() ?: return "брандмауэр: состояние не прочитано, не трогаю"
        val saved = readSaved()
        if (current.values.none { it }) {
            return if (saved != null) "брандмауэр: уже выключен, вернём при отключении" else "брандмауэр: уже выключен пользователем, не трогаю"
        }
        val toRestore = saved?.let { s -> PROFILES.associate { it.key to (s[it.key] == true || current[it.key] == true) } } ?: current
        try {
            writeSaved(toRestore)
        } catch (t: Throwable) {
            return "брандмауэр: не удалось сохранить прежнее состояние (${t.message}), не трогаю"
        }
        val (code, out) = runner("${netsh()} advfirewall set allprofiles state off", 20000)
        val after = readState()
        val off = after != null && after.values.none { it }
        if (code != 0 || (after != null && !off)) {
            // nothing changed (or not completely): put the profiles back and forget the state
            val back = restore()
            return "брандмауэр: НЕ выключен (код $code ${out.trim().take(120)}); $back"
        }
        return "брандмауэр: выключен на время работы туннеля (было: ${describe(toRestore)})"
    }

    /**
     * Puts the saved profiles back and forgets the saved state. Returns one line for the journal, or an empty string
     * when there was nothing to restore. On failure the saved state stays, and the next start tries again.
     */
    @Synchronized
    fun restore(): String {
        val saved = readSaved() ?: return ""
        val cmds = restoreCommands(saved)
        var ok = true
        val errors = ArrayList<String>()
        for (c in cmds) {
            val (code, out) = runner(netsh() + c.removePrefix("netsh"), 20000)
            if (code != 0) {
                ok = false
                errors.add("код $code ${out.trim().take(100)}")
            }
        }
        val after = readState()
        if (after != null && PROFILES.any { saved[it.key] == true && after[it.key] != true }) {
            ok = false
            errors.add("после команды профиль всё ещё выключен")
        }
        if (!ok) return "брандмауэр: НЕ восстановлен (${errors.joinToString("; ")}); повторим при следующем запуске LanBridge"
        stateFile().delete()
        return "брандмауэр: восстановлен (${describe(saved)})"
    }
}
