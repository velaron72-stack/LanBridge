package app.lanbridge.core

/**
 * JNI bridge to liblanbridge.so (C++ core). Text always crosses the boundary as UTF-8 bytes.
 *
 * Status array layout (LongArray, 32 fields; older builds of the core returned 23):
 *  0 state  1 rxBytes  2 txBytes  3 rxPkts  4 txPkts  5 rttMs(-1)  6 sinceRxMs(-1)  7 connectedSec  8 pathLocal(-1/0/1)
 *  9 bcastTx 10 bcastRx 11 mcastTx 12 mcastRx 13 authFail 14 punchRx 15 hsRx 16 dropped 17 mappingChanged
 * 18 myNat 19 peerNat 20 myExpiresAt 21 handshakes 22 peerLeft
 * 23 layoutVer (the TUN has to be set up again when it changes)  24 members  25 members connected
 * 26 groupRole (0 direct, 1 creator, 2 member)  27 joinState (0 none, 1 joining, 2 admitted, 3 refused)
 * 28 mySlot  29 joinUntil (unix s, creator)  30 packets relayed through the creator  31 memberListSettled (0/1)
 *
 * members(): one line per device, fields separated by TAB.
 *  S slot name ip4 ip6 profVer role
 *  M slot name state(1 connecting, 2 connected, 3 silent, 4 left) rttMs pathKind(0 none, 1 internet, 2 local, 3 via the
 *    creator) pathText ip4 ip6 profVer isCreator rxBytes txBytes connectedSec families(bit 0 IPv4, bit 1 IPv6)
 */
object Native {
    init {
        System.loadLibrary("lanbridge")
    }

    // ---- direct connection of two devices
    external fun prepare(stun: ByteArray, localIps: ByteArray, name: ByteArray, ttlSec: Int): ByteArray?
    external fun describeOffer(blob: ByteArray): ByteArray?
    external fun setPeer(blob: ByteArray): Int

    // ---- groups
    external fun prepareGroup(stun: ByteArray, localIps: ByteArray, name: ByteArray, ttlSec: Int): ByteArray?
    external fun renewGroup(ttlSec: Int): ByteArray?
    external fun joinGroup(blob: ByteArray): Int
    external fun swapTun(fd: Int): Int
    external fun setProfile(name: ByteArray, avatar: ByteArray): Boolean
    external fun members(): ByteArray?
    external fun memberAvatar(slot: Int): ByteArray?
    external fun hintTopic(): ByteArray?
    external fun sealHint(): ByteArray?
    external fun openHint(note: ByteArray): Int

    // ---- both modes
    external fun netLayout(): ByteArray?
    external fun start(tunFd: Int, mtu: Int): Int
    external fun retry()
    external fun stop()
    external fun status(): LongArray?
    external fun info(): ByteArray?
    external fun flows(): ByteArray?
    external fun resetFlows()
    external fun lastError(): ByteArray?
    external fun log(): ByteArray?
    external fun logLine(msg: ByteArray)
    external fun socketFd(): Int   // IPv4 socket of the tunnel, -1 when there is none
    external fun socketFd6(): Int  // IPv6 socket of the tunnel, -1 when there is none

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
