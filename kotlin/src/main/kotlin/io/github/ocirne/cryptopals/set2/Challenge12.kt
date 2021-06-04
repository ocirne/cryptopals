import io.github.ocirne.cryptopals.Basics
import io.github.ocirne.cryptopals.Basics.padding
import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import io.github.ocirne.cryptopals.Oracle
import io.github.ocirne.cryptopals.crypto.AES
import kotlin.random.Random

class Challenge12Oracle(val unknownString: String): Oracle {

    val key = Random.nextBytes(AES.BLOCK_SIZE)
    val aes = AES.ECB(key)

    override fun encrypt(pt: ByteArray): ByteArray {
        val padded = padding(pt + Basics.decodeFromBase64(unknownString))
        return aes.encrypt(padded)
    }
}

class Challenge12(val oracle : Oracle) {

    private fun discoverNextHop(oldBlockSize: Int): Int {
        var i = 1
        while (true) {
            val newBlockSize = oracle.encrypt(0x00.toByte().repeat(i)).size
            if (oldBlockSize < newBlockSize) {
                return newBlockSize
            }
            i++
        }
    }

    fun discoverBlockSize(): Int {
        val firstBlockSize = oracle.encrypt(byteArrayOf()).size
        val hop1 = discoverNextHop(firstBlockSize)
        val hop2 = discoverNextHop(hop1 + 1)
        return hop2 - hop1
    }

    fun discoverMode(): String {
        val secret = oracle.encrypt(0x00.toByte().repeat(32))
        return if (secret.slice(0..15) == secret.slice(16..31)) "ECB" else "CBC"
    }

    fun lookup(i: Int, knownSecret: ByteArray, knownContent: ByteArray): Byte? {
        for (b in 0..255) {
            val secret = oracle.encrypt(0x00.toByte().repeat(i) + knownContent + byteArrayOf(b.toByte()))
            if (secret.sliceArray(0..159).contentEquals(knownSecret)) {
                return b.toByte()
            }
        }
        return null
    }

    fun crack(): String {
        var known = byteArrayOf()
        for (i in 159 downTo 0) {
            val secret = oracle.encrypt(0x00.toByte().repeat(i))
            val b = lookup(i, secret.sliceArray(0..159), known) ?: return String(known)
            known += b
            print(b.toInt().toChar())
        }
        throw IllegalStateException()
    }
}
