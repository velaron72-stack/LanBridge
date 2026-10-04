package app.lanbridge.ui

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

object QrUtil {
    fun render(text: String, size: Int = 720): Bitmap? {
        return try {
            val hints = HashMap<EncodeHintType, Any>()
            hints[EncodeHintType.MARGIN] = 1
            hints[EncodeHintType.ERROR_CORRECTION] = ErrorCorrectionLevel.M
            val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
            val w = m.width
            val h = m.height
            val px = IntArray(w * h)
            for (y in 0 until h) {
                val row = y * w
                for (x in 0 until w) {
                    px[row + x] = if (m.get(x, y)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
                }
            }
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
            bmp.setPixels(px, 0, w, 0, 0, w, h)
            bmp
        } catch (_: Exception) {
            null
        }
    }
}
