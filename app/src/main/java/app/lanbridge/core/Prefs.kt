package app.lanbridge.core

import android.content.Context
import android.os.Build
import android.util.Base64

class Prefs(context: Context) {
    private val sp = context.applicationContext.getSharedPreferences("lanbridge", Context.MODE_PRIVATE)

    /** The name the other participants see. */
    var deviceName: String
        get() = sp.getString("name", null)?.takeIf { it.isNotBlank() } ?: (Build.MODEL ?: "Android")
        set(v) {
            sp.edit().putString("name", v.trim()).apply()
        }

    /** The avatar the other participants see: a small JPEG (at most [AVATAR_MAX] bytes), empty when there is none. */
    var avatar: ByteArray
        get() {
            val s = sp.getString("avatar", null) ?: return ByteArray(0)
            return try {
                Base64.decode(s, Base64.NO_WRAP)
            } catch (_: IllegalArgumentException) {
                ByteArray(0)
            }
        }
        set(v) {
            val e = sp.edit()
            if (v.isEmpty() || v.size > AVATAR_MAX) e.remove("avatar") else e.putString("avatar", Base64.encodeToString(v, Base64.NO_WRAP))
            e.apply()
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

    /** Group mode (true) or direct connection of two devices (false) is shown on the main screen. */
    var groupMode: Boolean
        get() = sp.getBoolean("groupMode", true)
        set(v) {
            sp.edit().putBoolean("groupMode", v).apply()
        }

    /**
     * Strict NAT help: a joining device leaves a small encrypted note on a public message board (ntfy.sh) and the
     * group's creator reads it. Only needed when the creator sits behind a NAT that drops the newcomer's first packets;
     * the note is sealed with a key derived from the group code and holds nothing but the newcomer's network addresses.
     */
    var hintMailbox: Boolean
        get() = sp.getBoolean("hintMailbox", true)
        set(v) {
            sp.edit().putBoolean("hintMailbox", v).apply()
        }

    /**
     * PC only: may the app switch Windows Firewall off while the tunnel is open? [FIREWALL_ASK] = the user has not been
     * asked yet, [FIREWALL_OFF] = yes (the previous state comes back when the tunnel closes), [FIREWALL_KEEP] = no.
     */
    var firewallMode: Int
        get() = sp.getInt("firewallMode", FIREWALL_ASK).coerceIn(FIREWALL_ASK, FIREWALL_KEEP)
        set(v) {
            sp.edit().putInt("firewallMode", v.coerceIn(FIREWALL_ASK, FIREWALL_KEEP)).apply()
        }

    companion object {
        const val FIREWALL_ASK = 0
        const val FIREWALL_OFF = 1
        const val FIREWALL_KEEP = 2
        const val DEFAULT_MTU = 1500
        const val AVATAR_MAX = 12288
        const val DEFAULT_STUN = "stun.l.google.com:19302\n" +
            "stun1.l.google.com:19302\n" +
            "stun.cloudflare.com:3478\n" +
            "stun.nextcloud.com:3478\n" +
            "stun.sipgate.net:3478"
    }
}
