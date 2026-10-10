package app.lanbridge

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import app.lanbridge.core.TunnelController

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        val ch = NotificationChannel(CHANNEL_TUNNEL, "Туннель", NotificationManager.IMPORTANCE_LOW)
        ch.description = "Состояние соединения LanBridge"
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        TunnelController.init(this)
    }

    companion object {
        const val CHANNEL_TUNNEL = "tunnel"
    }
}
