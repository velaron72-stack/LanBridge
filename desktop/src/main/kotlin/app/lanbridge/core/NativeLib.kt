package app.lanbridge.core

import java.io.File

/**
 * Loads lanbridge.dll. The file ships next to the app (the "resources" folder of the packaged app); the places are
 * tried one by one and the first hit is loaded by its absolute path, so the result does not depend on how the
 * launcher sets java.library.path. The current directory is never searched: the app runs as administrator.
 */
object NativeLib {
    @Volatile
    var dir: File? = null
        private set

    private var loaded = false

    @Synchronized
    fun load() {
        if (loaded) return
        val tried = ArrayList<String>()
        for (d in candidates()) {
            val f = File(d, "lanbridge.dll")
            tried.add(f.path)
            if (f.isFile) {
                System.load(f.absolutePath)
                dir = f.absoluteFile.parentFile
                loaded = true
                return
            }
        }
        try {
            System.loadLibrary("lanbridge")
            loaded = true
        } catch (e: UnsatisfiedLinkError) {
            throw UnsatisfiedLinkError("lanbridge.dll не найден (искал: " + tried.joinToString("; ") + ")")
        }
    }

    private fun candidates(): List<File> {
        val out = LinkedHashSet<File>()
        System.getProperty("lanbridge.native")?.takeIf { it.isNotBlank() }?.let { out.add(File(it)) }
        System.getProperty("compose.application.resources.dir")?.takeIf { it.isNotBlank() }?.let { out.add(File(it)) }
        try {
            val loc = NativeLib::class.java.protectionDomain?.codeSource?.location
            if (loc != null) {
                val where = File(loc.toURI())
                val base = if (where.isFile) where.parentFile else where
                out.add(File(base, "resources"))
                out.add(base)
                base.parentFile?.let {
                    out.add(File(it, "resources"))
                    out.add(it)
                }
            }
        } catch (_: Throwable) {
        }
        return out.toList()
    }
}
