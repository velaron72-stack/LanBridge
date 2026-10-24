package android.content

import java.io.File
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Properties

/**
 * Key-value settings kept in %APPDATA%\LanBridge\<name>.properties (UTF-8). Same calls as the Android class:
 * getString/getInt/getBoolean and edit().put...().apply().
 */
class SharedPreferences private constructor(private val file: File) {
    private val values = LinkedHashMap<String, String>()

    init {
        try {
            if (file.isFile) {
                InputStreamReader(file.inputStream(), StandardCharsets.UTF_8).use { r ->
                    val p = Properties()
                    p.load(r)
                    for (k in p.stringPropertyNames()) values[k] = p.getProperty(k)
                }
            }
        } catch (_: Exception) {
        }
    }

    @Synchronized
    fun getString(key: String, default: String?): String? = values[key] ?: default

    @Synchronized
    fun getInt(key: String, default: Int): Int = values[key]?.toIntOrNull() ?: default

    @Synchronized
    fun getBoolean(key: String, default: Boolean): Boolean = values[key]?.let { it == "true" } ?: default

    fun edit(): Editor = Editor()

    @Synchronized
    private fun commit(puts: Map<String, String?>) {
        for ((k, v) in puts) if (v == null) values.remove(k) else values[k] = v
        try {
            file.parentFile?.mkdirs()
            val p = Properties()
            for ((k, v) in values) p.setProperty(k, v)
            val tmp = File(file.parentFile, file.name + ".tmp")
            OutputStreamWriter(tmp.outputStream(), StandardCharsets.UTF_8).use { p.store(it, "LanBridge") }
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)
        } catch (_: Exception) {
        }
    }

    inner class Editor {
        private val puts = LinkedHashMap<String, String?>()

        fun putString(key: String, value: String?): Editor {
            puts[key] = value
            return this
        }

        fun putInt(key: String, value: Int): Editor {
            puts[key] = value.toString()
            return this
        }

        fun putBoolean(key: String, value: Boolean): Editor {
            puts[key] = value.toString()
            return this
        }

        fun remove(key: String): Editor {
            puts[key] = null
            return this
        }

        fun apply() {
            commit(puts)
        }
    }

    companion object {
        private val open = HashMap<String, SharedPreferences>()

        /** The folder of the settings: %APPDATA%\LanBridge, or ~/.lanbridge when there is no APPDATA. */
        fun dataDir(): File {
            val appData = System.getenv("APPDATA")
            return if (!appData.isNullOrBlank()) File(appData, "LanBridge") else File(System.getProperty("user.home"), ".lanbridge")
        }

        @Synchronized
        fun open(name: String): SharedPreferences = open.getOrPut(name) { SharedPreferences(File(dataDir(), "$name.properties")) }
    }
}
