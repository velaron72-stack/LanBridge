package app.lanbridge.ui

import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.awt.RenderingHints
import java.awt.image.BufferedImage
import java.io.File
import javax.imageio.ImageIO

object QrUtil {
    /** The QR code of [text] as a picture for the screen, or null when the text cannot be encoded. */
    fun render(text: String, size: Int = 720): ImageBitmap? {
        return try {
            val hints = HashMap<EncodeHintType, Any>()
            hints[EncodeHintType.MARGIN] = 1
            hints[EncodeHintType.ERROR_CORRECTION] = ErrorCorrectionLevel.M
            val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
            val img = BufferedImage(m.width, m.height, BufferedImage.TYPE_INT_RGB)
            for (y in 0 until m.height) {
                for (x in 0 until m.width) img.setRGB(x, y, if (m.get(x, y)) 0x000000 else 0xFFFFFF)
            }
            img.toComposeImageBitmap()
        } catch (_: Exception) {
            null
        }
    }

    /** The text of the QR code found in the picture, or null. Screenshots of a whole screen are scaled down when needed. */
    fun decode(image: BufferedImage): String? {
        var cur = image
        for (round in 0 until 4) {
            val text = decodeOnce(cur)
            if (text != null) return text
            if (cur.width < 400 || cur.height < 400) break
            cur = scaled(cur, cur.width / 2, cur.height / 2)
        }
        return null
    }

    fun decodeFile(file: File): String? = try {
        val img = ImageIO.read(file)
        if (img == null) null else decode(img)
    } catch (_: Throwable) {
        null
    }

    private fun decodeOnce(img: BufferedImage): String? {
        val w = img.width
        val h = img.height
        val px = IntArray(w * h)
        img.getRGB(0, 0, w, h, px, 0, w)
        val hints = HashMap<DecodeHintType, Any>()
        hints[DecodeHintType.TRY_HARDER] = true
        hints[DecodeHintType.CHARACTER_SET] = "UTF-8"
        val source = RGBLuminanceSource(w, h, px)
        for (src in listOf(source, source.invert())) {
            try {
                return QRCodeReader().decode(BinaryBitmap(HybridBinarizer(src)), hints).text
            } catch (_: Exception) {
            }
        }
        return null
    }

    private fun scaled(src: BufferedImage, w: Int, h: Int): BufferedImage {
        val out = BufferedImage(w, h, BufferedImage.TYPE_INT_RGB)
        val g = out.createGraphics()
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR)
        g.drawImage(src, 0, 0, w, h, null)
        g.dispose()
        return out
    }
}
