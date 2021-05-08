package io.github.ocirne.cryptopals.set4

import io.github.ocirne.cryptopals.Basics.encodeHexString
import java.lang.IllegalStateException


/**
 * see
 * - https://de.wikipedia.org/wiki/Secure_Hash_Algorithm
 * - https://en.wikipedia.org/wiki/SHA-1
 */
@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
class Challenge28 {

    private var h0 = 0x67452301u
    private var h1 = 0xEFCDAB89u
    private var h2 = 0x98BADCFEu
    private var h3 = 0x10325476u
    private var h4 = 0xC3D2E1F0u

    private fun List<Byte>.concatToUInt(): UInt =
        (this[0].toUInt() shl 24) or (this[1].toUInt() shl 16) or (this[2].toUInt() shl 8) or this[3].toUInt()

    private fun UInt.splitToBytes(): ByteArray =
        byteArrayOf(
            (this shr 24).toByte(),
            (this shr 16).toByte(),
            (this shr 8).toByte(),
            this.toByte())

    private fun ULong.splitToBytes(): ByteArray =
        byteArrayOf(
            (this shr 56).toByte(),
            (this shr 48).toByte(),
            (this shr 40).toByte(),
            (this shr 32).toByte(),
            (this shr 24).toByte(),
            (this shr 16).toByte(),
            (this shr 8).toByte(),
            this.toByte())

    private fun preprocess(message: String): ByteArray {
        var msg = message.toByteArray()
        // ml = message length in bits, 64 bit quantity
        val ml = msg.size.toULong() * 8u
        // append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
        msg += 0x80.toByte()
        // append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512)
        msg += "\u0000".repeat((((448u - (ml + 8u) % 512u) % 512u) / 8u).toInt()).toByteArray()
        // append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
        // ml - 64 bit
        msg += ml.splitToBytes()
        return msg
    }

    fun sha1(message: String): String {
        println(h0)
        val preprocessedMessage = preprocess(message)
        // Process the message in successive 512-bit chunks:
        preprocessedMessage.asIterable().chunked(64).forEach { chunk ->
            // break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
            val w = chunk.chunked(4).map { fourBytes -> fourBytes.concatToUInt() }.toUIntArray().toMutableList()

            assert (w.size == 16)

            // Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
            IntRange(16, 79).forEach { i ->
                w += (w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16]).rotateLeft(1)
            }
            // Initialize hash value for this chunk:
            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4
            var f: UInt
            var k: UInt
            // Main loop:[3][57]
            IntRange(0, 79).forEach { i ->
                when (i) {
                    in 0..19 -> {
                        f = d xor (b and (c xor d))
                        k = 0x5A827999u
                    }
                    in 20..39 -> {
                        f = b xor c xor d
                        k = 0x6ED9EBA1u
                    }
                    in 40..59 -> {
                        f = (b and c) or (b and d) or (c and d)
                        k = 0x8F1BBCDCu
                    }
                    in 60..79 -> {
                        f = b xor c xor d
                        k = 0xCA62C1D6u
                    }
                    else -> throw IllegalStateException()
                }
                val temp = (a.rotateLeft(5) + f + e + k + w[i])
                e = d
                d = c
                c = b.rotateLeft(30)
                b = a
                a = temp
            }
            // Add this chunk's hash to result so far:
            h0 += a
            h1 += b
            h2 += c
            h3 += d
            h4 += e
        }
        // Produce the final hash value (big-endian) as a 160-bit number:
        return encodeHexString(h0.splitToBytes() + h1.splitToBytes() + h2.splitToBytes() + h3.splitToBytes() + h4.splitToBytes())
    }
}
