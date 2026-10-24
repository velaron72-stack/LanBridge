package android.content

import app.lanbridge.vpn.TunnelVpnService

/**
 * The few members of android.content.Context that the shared core code (Prefs, TunnelController) uses, so that code
 * compiles unchanged for the desktop. There is one context: the process.
 */
open class Context {
    val applicationContext: Context get() = this

    fun getSharedPreferences(name: String, mode: Int): SharedPreferences = SharedPreferences.open(name)

    /** On Android this starts the VPN service; here it hands the command to the tunnel service of the process. */
    fun startService(intent: Intent): Any? {
        TunnelVpnService.dispatch(intent)
        return null
    }

    companion object {
        const val MODE_PRIVATE = 0
    }
}
