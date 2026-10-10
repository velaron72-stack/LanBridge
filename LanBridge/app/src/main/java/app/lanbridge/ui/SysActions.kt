package app.lanbridge.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings

object SysActions {
    /** "06.10 13:05": when this build was installed, to tell new and old builds apart. */
    @Suppress("DEPRECATION")
    fun installedAt(ctx: Context): String = try {
        val t = ctx.packageManager.getPackageInfo(ctx.packageName, 0).lastUpdateTime
        java.text.SimpleDateFormat("dd.MM HH:mm", java.util.Locale.getDefault()).format(java.util.Date(t))
    } catch (_: Exception) {
        ""
    }

    @Suppress("DEPRECATION")
    fun versionName(ctx: Context): String = try {
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: ""
    } catch (_: Exception) {
        ""
    }

    /** "2.0.0 (сборка 20003)": both phones must run the same build. */
    @Suppress("DEPRECATION")
    fun versionLabel(ctx: Context): String = try {
        val pi = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        "${pi.versionName ?: ""} (сборка ${pi.versionCode})"
    } catch (_: Exception) {
        versionName(ctx)
    }

    fun copy(ctx: Context, text: String) {
        try {
            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("LanBridge", text))
        } catch (_: Exception) {
        }
    }

    fun paste(ctx: Context): String {
        return try {
            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = cm.primaryClip
            if (clip == null || clip.itemCount == 0) "" else (clip.getItemAt(0).coerceToText(ctx)?.toString() ?: "")
        } catch (_: Exception) {
            ""
        }
    }

    fun share(ctx: Context, text: String) {
        try {
            val i = Intent(Intent.ACTION_SEND)
            i.type = "text/plain"
            i.putExtra(Intent.EXTRA_TEXT, text)
            val chooser = Intent.createChooser(i, "Отправить код")
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(chooser)
        } catch (_: Exception) {
        }
    }

    fun isIgnoringBatteryOptimizations(ctx: Context): Boolean = try {
        (ctx.getSystemService(Context.POWER_SERVICE) as PowerManager).isIgnoringBatteryOptimizations(ctx.packageName)
    } catch (_: Exception) {
        false
    }

    fun requestIgnoreBatteryOptimizations(ctx: Context) {
        try {
            val i = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + ctx.packageName))
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(i)
        } catch (_: Exception) {
            appSettings(ctx)
        }
    }

    fun appSettings(ctx: Context) {
        try {
            val i = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + ctx.packageName))
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(i)
        } catch (_: Exception) {
        }
    }

    /** Tries the vendor "autostart" screens (MIUI, EMUI/Honor, ColorOS, Funtouch, ...). Returns false if none opened. */
    fun openAutostart(ctx: Context): Boolean {
        val targets = listOf(
            "com.miui.securitycenter" to "com.miui.permcenter.autostart.AutoStartManagementActivity",
            "com.huawei.systemmanager" to "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity",
            "com.hihonor.systemmanager" to "com.hihonor.systemmanager.startupmgr.ui.StartupNormalAppListActivity",
            "com.coloros.safecenter" to "com.coloros.safecenter.permission.startup.StartupAppListActivity",
            "com.oppo.safe" to "com.oppo.safe.permission.startup.StartupAppListActivity",
            "com.vivo.permissionmanager" to "com.vivo.permissionmanager.activity.BgStartUpManagerActivity",
            "com.samsung.android.lool" to "com.samsung.android.sm.ui.battery.BatteryActivity",
        )
        for (t in targets) {
            try {
                val i = Intent()
                i.component = ComponentName(t.first, t.second)
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                ctx.startActivity(i)
                return true
            } catch (_: Exception) {
            }
        }
        return false
    }
}
