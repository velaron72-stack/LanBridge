package app.lanbridge.core

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import java.io.ByteArrayOutputStream

/** Turns a picture chosen in the gallery into the small square JPEG that is sent to the other participants. */
object AvatarUtil {
    private const val SIDE = 128

    /** A square JPEG of at most [Prefs.AVATAR_MAX] bytes made from the image behind [uri], or null if it cannot be read. */
    fun fromUri(ctx: Context, uri: Uri): ByteArray? {
        return try {
            val cr = ctx.contentResolver
            val bounds = BitmapFactory.Options()
            bounds.inJustDecodeBounds = true
            cr.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
            var sample = 1
            while (bounds.outWidth / (sample * 2) >= SIDE * 2 && bounds.outHeight / (sample * 2) >= SIDE * 2) sample *= 2
            val opts = BitmapFactory.Options()
            opts.inSampleSize = sample
            val decoded = cr.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) } ?: return null
            var degrees = 0
            try {
                val ori = cr.openInputStream(uri)?.use {
                    ExifInterface(it).getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
                } ?: ExifInterface.ORIENTATION_NORMAL
                degrees = when (ori) {
                    ExifInterface.ORIENTATION_ROTATE_90 -> 90
                    ExifInterface.ORIENTATION_ROTATE_180 -> 180
                    ExifInterface.ORIENTATION_ROTATE_270 -> 270
                    else -> 0
                }
            } catch (_: Exception) {
            }
            var bmp: Bitmap = decoded
            if (degrees != 0) {
                val m = Matrix()
                m.postRotate(degrees.toFloat())
                bmp = Bitmap.createBitmap(decoded, 0, 0, decoded.width, decoded.height, m, true)
            }
            val side = minOf(bmp.width, bmp.height)
            val square = Bitmap.createBitmap(bmp, (bmp.width - side) / 2, (bmp.height - side) / 2, side, side)
            for (px in intArrayOf(SIDE, 96, 64)) {
                val flat = flatten(square, px)
                for (q in intArrayOf(88, 76, 64, 52, 40)) {
                    val out = ByteArrayOutputStream()
                    flat.compress(Bitmap.CompressFormat.JPEG, q, out)
                    val bytes = out.toByteArray()
                    if (bytes.size <= Prefs.AVATAR_MAX - 256) return bytes
                }
            }
            null
        } catch (_: Throwable) {
            null
        }
    }

    /** Scales to [px] and puts the picture on a white background (JPEG has no transparency). */
    private fun flatten(src: Bitmap, px: Int): Bitmap {
        val scaled = Bitmap.createScaledBitmap(src, px, px, true)
        val out = Bitmap.createBitmap(px, px, Bitmap.Config.ARGB_8888)
        val c = Canvas(out)
        c.drawColor(Color.WHITE)
        c.drawBitmap(scaled, 0f, 0f, null)
        return out
    }
}
