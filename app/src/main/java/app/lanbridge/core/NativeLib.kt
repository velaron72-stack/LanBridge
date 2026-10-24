package app.lanbridge.core

/** Loads the C++ core. The desktop build has its own version of this file that finds lanbridge.dll next to the app. */
object NativeLib {
    fun load() {
        System.loadLibrary("lanbridge")
    }
}
