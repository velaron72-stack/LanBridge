package app.lanbridge.core

import android.content.Context
import android.os.Build

class Prefs(context: Context) {
    private val sp = context.applicationContext.getSharedPreferences("lanbridge", Context.MODE_PRIVATE)

    var deviceName: String
        get() = sp.getString("name", null)?.takeIf { it.isNotBlank() } ?: (Build.MODEL ?: "Android")
        set(v) {
            sp.edit().putString("name", v.trim()).apply()
        }

    var stunServers: String
        get() = sp.getString("stun", null)?.takeIf { it.isNotBlank() } ?: DEFAULT_STUN
        set(v) {
            sp.edit().putString("stun", v.trim()).apply()
        }

    /**
     * TUN MTU. 1500 by default: the tunnel cuts packets above 1339 bytes into chunks itself, so the network never
     * fragments anything. The key is new on purpose: values chosen for the old 1280 default are not carried over.
     */
    var mtu: Int
        get() = sp.getInt("mtu15", DEFAULT_MTU).coerceIn(1200, 1500)
        set(v) {
            sp.edit().putInt("mtu15", v.coerceIn(1200, 1500)).apply()
        }

    var ttlMin: Int
        get() = sp.getInt("ttl", 10).coerceIn(2, 60)
        set(v) {
            sp.edit().putInt("ttl", v.coerceIn(2, 60)).apply()
        }

    var keepAwake: Boolean
        get() = sp.getBoolean("awake", true)
        set(v) {
            sp.edit().putBoolean("awake", v).apply()
        }

    companion object {
        const val DEFAULT_MTU = 1500
        const val DEFAULT_STUN = "stun.l.google.com:19302\n" +
            "stun1.l.google.com:19302\n" +
            "stun.cloudflare.com:3478\n" +
            "stun.nextcloud.com:3478\n" +
            "stun.sipgate.net:3478"
    }
}
