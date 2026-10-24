package app.lanbridge.core

import java.awt.Color
import java.awt.RenderingHints
import java.awt.geom.AffineTransform
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.File
import javax.imageio.IIOImage
import javax.imageio.ImageIO
import javax.imageio.ImageWriteParam

/** Turns a picture chosen on the PC into the small square JPEG that is sent to the other participants. */
object AvatarUtil {
    private const val SIDE = 128

    /** A square JPEG of at most [Prefs.AVATAR_MAX] bytes made from the image file, or null if it cannot be read. */
    fun fromFile(file: File): ByteArray? {
        return try {
            val raw = file.readBytes()
            val decoded = ImageIO.read(raw.inputStream()) ?: return null
            val rotated = rotate(decoded, exifOrientation(raw))
            val side = minOf(rotated.width, rotated.height)
            val square = rotated.getSubimage((rotated.width - side) / 2, (rotated.height - side) / 2, side, side)
            for (px in intArrayOf(SIDE, 96, 64)) {
                val flat = flatten(square, px)
                for (q in intArrayOf(88, 76, 64, 52, 40)) {
                    val bytes = jpeg(flat, q)
                    if (bytes.size <= Prefs.AVATAR_MAX - 256) return bytes
                }
            }
            null
        } catch (_: Throwable) {
            null
        }
    }

    /** Scales to [px] and puts the picture on a white background (JPEG has no transparency). */
    private fun flatten(src: BufferedImage, px: Int): BufferedImage {
        val out = BufferedImage(px, px, BufferedImage.TYPE_INT_RGB)
        val g = out.createGraphics()
        g.color = Color.WHITE
        g.fillRect(0, 0, px, px)
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC)
        g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY)
        // large pictures are halved first: one bicubic step from 4000 px leaves only a handful of source pixels per target pixel
        var cur = src
        while (cur.width / 2 >= px * 2) {
            val half = BufferedImage(cur.width / 2, cur.height / 2, BufferedImage.TYPE_INT_ARGB)
            val hg = half.createGraphics()
            hg.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR)
            hg.drawImage(cur, 0, 0, half.width, half.height, null)
            hg.dispose()
            cur = half
        }
        g.drawImage(cur, 0, 0, px, px, null)
        g.dispose()
        return out
    }

    private fun jpeg(img: BufferedImage, quality: Int): ByteArray {
        val writer = ImageIO.getImageWritersByFormatName("jpeg").next()
        val p = writer.defaultWriteParam
        p.compressionMode = ImageWriteParam.MODE_EXPLICIT
        p.compressionQuality = quality / 100f
        val out = ByteArrayOutputStream()
        ImageIO.createImageOutputStream(out).use { ios ->
            writer.output = ios
            writer.write(null, IIOImage(img, null, null), p)
        }
        writer.dispose()
        return out.toByteArray()
    }

    private fun rotate(src: BufferedImage, orientation: Int): BufferedImage {
        val degrees = when (orientation) {
            3 -> 180
            6 -> 90
            8 -> 270
            else -> return src
        }
        val w = src.width
        val h = src.height
        val swap = degrees != 180
        val out = BufferedImage(if (swap) h else w, if (swap) w else h, BufferedImage.TYPE_INT_ARGB)
        val g = out.createGraphics()
        val t = AffineTransform()
        t.translate(out.width / 2.0, out.height / 2.0)
        t.rotate(Math.toRadians(degrees.toDouble()))
        t.translate(-w / 2.0, -h / 2.0)
        g.drawImage(src, t, null)
        g.dispose()
        return out
    }

    /** The EXIF orientation of a JPEG (1 = upright), 1 when there is none. */
    private fun exifOrientation(b: ByteArray): Int {
        if (b.size < 12 || b[0] != 0xFF.toByte() || b[1] != 0xD8.toByte()) return 1
        var i = 2
        while (i + 4 < b.size) {
            if (b[i] != 0xFF.toByte()) return 1
            val marker = b[i + 1].toInt() and 0xFF
            val len = ((b[i + 2].toInt() and 0xFF) shl 8) or (b[i + 3].toInt() and 0xFF)
            if (marker == 0xE1 && len >= 16 && i + 10 < b.size && String(b, i + 4, 4, Charsets.US_ASCII) == "Exif") {
                val t = i + 10
                if (t + 8 > b.size) return 1
                val le = b[t] == 'I'.code.toByte()
                fun u16(o: Int): Int =
                    if (le) (b[o].toInt() and 255) or ((b[o + 1].toInt() and 255) shl 8)
                    else ((b[o].toInt() and 255) shl 8) or (b[o + 1].toInt() and 255)
                fun u32(o: Int): Int = if (le) u16(o) or (u16(o + 2) shl 16) else (u16(o) shl 16) or u16(o + 2)
                val ifd = t + u32(t + 4)
                if (ifd < 0 || ifd + 2 > b.size) return 1
                val n = u16(ifd)
                for (k in 0 until n) {
                    val e = ifd + 2 + k * 12
                    if (e + 12 > b.size) break
                    if (u16(e) == 0x0112) return u16(e + 8)
                }
                return 1
            }
            if (marker == 0xDA) return 1
            i += 2 + len
        }
        return 1
    }
}
