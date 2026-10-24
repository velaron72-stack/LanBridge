package android.os

/** What the shared code reads from android.os.Build, answered for a PC. MODEL is the computer name (the default device name). */
object Build {
    const val MANUFACTURER = "PC"

    val MODEL: String? = (System.getenv("COMPUTERNAME") ?: System.getenv("HOSTNAME"))?.takeIf { it.isNotBlank() }

    object VERSION {
        val RELEASE: String = System.getProperty("os.version") ?: ""
    }
}
