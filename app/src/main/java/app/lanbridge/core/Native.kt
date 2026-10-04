package app.lanbridge.core

/**
 * JNI bridge to liblanbridge.so (C++ core). Text always crosses the boundary as UTF-8 bytes.
 *
 * Status array layout (LongArray):
 *  0 state  1 rxBytes  2 txBytes  3 rxPkts  4 txPkts  5 rttMs(-1)  6 sinceRxMs(-1)  7 connectedSec  8 pathLocal(-1/0/1)
 *  9 bcastTx 10 bcastRx 11 mcastTx 12 mcastRx 13 authFail 14 punchRx 15 hsRx 16 dropped 17 mappingChanged
 * 18 myNat 19 peerNat 20 myExpiresAt 21 handshakes 22 peerLeft
 */
object Native {
    init {
        System.loadLibrary("lanbridge")
    }

    external fun prepare(stun: ByteArray, localIps: ByteArray, name: ByteArray, ttlSec: Int): ByteArray?
    external fun describeOffer(blob: ByteArray): ByteArray?
    external fun setPeer(blob: ByteArray): Int
    external fun layout(): ByteArray?
    external fun start(tunFd: Int, password: ByteArray, mtu: Int): Int
    external fun retry()
    external fun stop()
    external fun status(): LongArray?
    external fun info(): ByteArray?
    external fun lastError(): ByteArray?
    external fun log(): ByteArray?
    external fun logLine(msg: ByteArray)
    external fun socketFd(): Int

    fun text(b: ByteArray?): String = if (b == null) "" else String(b, Charsets.UTF_8)

    fun kv(b: ByteArray?): Map<String, String> {
        val out = HashMap<String, String>()
        for (line in text(b).split('\n')) {
            val i = line.indexOf('=')
            if (i > 0) out[line.substring(0, i)] = line.substring(i + 1)
        }
        return out
    }

    fun note(msg: String) {
        logLine(msg.toByteArray(Charsets.UTF_8))
    }
}
