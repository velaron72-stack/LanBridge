package app.lanbridge.ui

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import java.awt.Image
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import java.awt.image.BufferedImage
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.Properties

/** What the screens ask of the system: clipboard, file dialogs, version texts. Same calls as on the phone. */
object SysActions {
    /** A short message for the bottom of the window ("Скопировано"); the main screen shows it and clears it. */
    val notice = MutableStateFlow<String?>(null)

    private val props: Properties by lazy {
        val p = Properties()
        try {
            SysActions::class.java.getResourceAsStream("/version.properties")?.use { p.load(it) }
        } catch (_: Exception) {
        }
        p
    }

    /** "PC-NAME, Windows 11 10.0 (amd64)": the computer as the log shows it. */
    fun platformLabel(): String =
        "${System.getenv("COMPUTERNAME") ?: "PC"}, ${System.getProperty("os.name")} ${System.getProperty("os.version")} (${System.getProperty("os.arch")})"

    /** "06.10 13:05": when this build was put on the disk, to tell new and old builds apart. */
    @Suppress("UNUSED_PARAMETER")
    fun installedAt(ctx: Context): String = try {
        val exe = ProcessHandle.current().info().command().orElse(null)
        val f = if (exe != null) File(exe) else null
        if (f != null && f.isFile) SimpleDateFormat("dd.MM HH:mm", Locale.getDefault()).format(Date(f.lastModified())) else ""
    } catch (_: Exception) {
        ""
    }

    @Suppress("UNUSED_PARAMETER")
    fun versionName(ctx: Context): String = props.getProperty("versionName") ?: ""

    /** "2.1.0 (сборка 20005)": all devices must run the same build. */
    fun versionLabel(ctx: Context): String = "${versionName(ctx)} (сборка ${props.getProperty("versionCode") ?: "?"})"

    @Suppress("UNUSED_PARAMETER")
    fun copy(ctx: Context, text: String) {
        try {
            Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
            notice.value = "Скопировано"
        } catch (_: Exception) {
            notice.value = "Не удалось записать в буфер обмена"
        }
    }

    /** The text on the clipboard; a picture with a QR code on it (a screenshot) gives the text of the code. */
    @Suppress("UNUSED_PARAMETER")
    fun paste(ctx: Context): String {
        return try {
            val cb = Toolkit.getDefaultToolkit().systemClipboard
            if (cb.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                (cb.getData(DataFlavor.stringFlavor) as? String) ?: ""
            } else if (cb.isDataFlavorAvailable(DataFlavor.imageFlavor)) {
                val img = cb.getData(DataFlavor.imageFlavor) as? Image
                val text = if (img != null) QrUtil.decode(toBuffered(img)) else null
                if (text == null) notice.value = "В буфере обмена нет текста и QR-кода"
                text ?: ""
            } else {
                ""
            }
        } catch (_: Exception) {
            ""
        }
    }

    /** There is no system share sheet on a PC: the text goes to the clipboard, ready to be pasted into a messenger. */
    @Suppress("UNUSED_PARAMETER")
    fun share(ctx: Context, text: String) {
        try {
            Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
            notice.value = "Код скопирован: вставьте его в сообщение"
        } catch (_: Exception) {
            notice.value = "Не удалось записать в буфер обмена"
        }
    }

    /** Asks for a picture with the standard Windows dialog. Null when the choice was cancelled. */
    fun pickImage(title: String): File? {
        return try {
            val d = java.awt.FileDialog(null as java.awt.Frame?, title, java.awt.FileDialog.LOAD)
            d.setFilenameFilter { _, name ->
                val n = name.lowercase()
                n.endsWith(".png") || n.endsWith(".jpg") || n.endsWith(".jpeg") || n.endsWith(".bmp") || n.endsWith(".gif")
            }
            d.isVisible = true
            val f = d.file
            val dir = d.directory
            if (f == null || dir == null) null else File(dir, f)
        } catch (_: Throwable) {
            null
        }
    }

    private fun toBuffered(img: Image): BufferedImage {
        if (img is BufferedImage) return img
        val w = img.getWidth(null)
        val h = img.getHeight(null)
        val out = BufferedImage(maxOf(w, 1), maxOf(h, 1), BufferedImage.TYPE_INT_RGB)
        val g = out.createGraphics()
        g.drawImage(img, 0, 0, null)
        g.dispose()
        return out
    }
}
