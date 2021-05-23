package io.github.ocirne.cryptopals

import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import io.github.ocirne.cryptopals.Basics.encodeHexString
import io.github.ocirne.cryptopals.Basics.xor
import kotlin.math.abs
import kotlin.math.sin

@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
interface Digest {
    fun digest(message: ByteArray): ByteArray
    fun digest(message: String): ByteArray = digest(message.toByteArray())

    fun hexdigest(message: ByteArray): String
    fun hexdigest(message: String): String = hexdigest(message.toByteArray())
}

private fun List<UByte>.concatToUInt(): UInt =
    (this[0].toUInt() shl 24) or (this[1].toUInt() shl 16) or (this[2].toUInt() shl 8) or this[3].toUInt()

private fun String.toUByteArray(): UByteArray =
    this.toByteArray().toUByteArray()

private fun UInt.splitToUByteArray(): UByteArray =
    (24 downTo 0 step 8).map { b -> (this shr b).toUByte() }.toUByteArray()

private fun ULong.splitToUByteArray(): UByteArray =
    (56 downTo 0 step 8).map { b -> (this shr b).toUByte() }.toUByteArray()


/**
 * see
 * - https://de.wikipedia.org/wiki/Secure_Hash_Algorithm
 * - https://en.wikipedia.org/wiki/SHA-1
 */
@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
class SHA1(
    val i0: UInt = 0x67452301u,
    val i1: UInt = 0xEFCDAB89u,
    val i2: UInt = 0x98BADCFEu,
    val i3: UInt = 0x10325476u,
    val i4: UInt = 0xC3D2E1F0u,
    val pa: Int = 0
) : Digest {

    private fun preprocess(message: ByteArray): UByteArray {
        var msg = message.toUByteArray()
        // ml = message length in bits, 64 bit quantity
        val messageLengthByteArray = msg.size.toULong()
        // append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
        msg += 0x80.toUByte()
        // append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512)
        msg += "\u0000".repeat(((56u - (messageLengthByteArray + 1u) and 0x3Fu) and 0x3Fu).toInt()).toUByteArray()
        // append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
        // ml - 64 bit
        msg += (messageLengthByteArray * 8u).splitToUByteArray()
        return msg
    }

    private fun _digest(message: ByteArray): Array<UInt> {
        // Initialize variables:
        var h0 = i0
        var h1 = i1
        var h2 = i2
        var h3 = i3
        var h4 = i4

        val preprocessedMessage = preprocess(message)
        // Process the message in successive 512-bit chunks:
        preprocessedMessage.asIterable().chunked(64).forEach { chunk ->
            // break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
            val w = chunk.chunked(4).map { fourByteArray -> fourByteArray.concatToUInt() }.toMutableList()
            // Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
            for (i in 16..79) {
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
            for (i in 0..79) {
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
                val temp = a.rotateLeft(5) + f + e + k + w[i]
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
        return arrayOf(h0, h1, h2, h3, h4)
    }

    override fun digest(message: ByteArray): ByteArray {
        val hh = _digest(message)
        return hh.map { h -> h.splitToUByteArray() }.flatten().toUByteArray().asByteArray()
    }

    override fun hexdigest(message: ByteArray): String {
        // Produce the final hash value (big-endian) as a 160-bit hex value:
        return encodeHexString(digest(message))
    }
}

@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
class MD5(
    val a: UInt = 0x67452301u,
    val b: UInt = 0xEFCDAB89u,
    val c: UInt = 0x98BADCFEu,
    val d: UInt = 0x10325476u,
    val pa: Int = 0
) : Digest {

    private fun preprocess(message: ByteArray): UByteArray {
        var msg = message.toUByteArray()
        // ml = message length in bits
        val messageLengthByteArray = (msg.size + pa).toULong()
        // Pre - processing: adding a single 1 bit
        msg += 0x80.toUByte()
        // Pre - processing: padding with zeros
        msg += "\u0000".repeat(((56u - (messageLengthByteArray + 1u) and 0x3Fu) and 0x3Fu).toInt()).toUByteArray()
        // append original length in bits mod 264 to message
        msg += (messageLengthByteArray * 8u).splitToUByteArray()
        return msg
    }

    fun _digest(message: ByteArray): Array<UInt> {
        // s specifies the per-round shift amounts
        val s = listOf(7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22) +
                listOf(5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20) +
                listOf(4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23) +
                listOf(6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21)

        // Use binary integer part of the sines of integers (Radians) as constants:
        val k = (0u..63u).map { i -> ((2 shl 32) * abs(sin(i.toDouble() + 1.0))).toUInt() }

        // Initialize variables:
        var a0 = a
        var b0 = b
        var c0 = c
        var d0 = d

        val preprocessedMessage = preprocess(message)
        // Process the message in successive 512-bit chunks:
        preprocessedMessage.asIterable().chunked(64).forEach { chunk ->
            // break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15
            val m = chunk.chunked(4).map { fourByteArray -> fourByteArray.concatToUInt() }.toMutableList()
            // Initialize hash value for this chunk:
            var a = a0
            var b = b0
            var c = c0
            var d = d0

            var f: UInt
            var g: UInt
            // Main loop:
            for (i in 0..63) {
                val j = i.toUInt()
                when (i) {
                    in 0..15 -> {
                        f = d xor (b and (c xor d))
                        g = j
                    }
                    in 16..31 -> {
                        f = c xor (d and (b xor c))
                        g = (5u * j + 1u) and 0xFu
                    }
                    in 32..47 -> {
                        f = b xor c xor d
                        g = (3u * j + 5u) and 0xFu
                    }
                    in 48..63 -> {
                        f = c xor (b or (d.inv()))
                        g = (7u * j) and 0xFu
                    }
                    else -> throw IllegalStateException()
                }
                // Be wary of the below definitions of a,b,c,d
                f += a + k[i] + m[g.toInt()]  // M[g] must be a 32-bits block
                a = d
                d = c
                c = b
                b += f.rotateLeft(s[i])
            }

            // Add this chunk's hash to result so far:
            a0 += a
            b0 += b
            c0 += c
            d0 += d
        }
        return arrayOf(a0, b0, c0, d0)
    }

    override fun digest(message: ByteArray): ByteArray {
        val hh = _digest(message)
        return hh.map { h -> h.splitToUByteArray() }.flatten().toUByteArray().asByteArray()
    }

    override fun hexdigest(message: ByteArray): String {
        return encodeHexString(digest(message))
    }
}

/**
 * see
 * - https://en.wikipedia.org/wiki/HMAC
 * - https://datatracker.ietf.org/doc/html/rfc2202
 */
@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
fun hmac(origKey: ByteArray, message: ByteArray, mac: Digest, blockSize: Int): String {
    // Keys longer than blockSize are shortened by hashing them
    var key = if (origKey.size > blockSize) mac.digest(origKey) else origKey

    // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if (key.size < blockSize) {
        key += 0x00.toByte().repeat((blockSize - key.size))  // Pad key with zeros to make it blockSize ByteArray long
    }
    val oKeyPad = xor(key, 0x5c.toByte().repeat(blockSize))  // Outer padded key
    val iKeyPad = xor(key, 0x36.toByte().repeat(blockSize))  // Inner padded key

    return mac.hexdigest(oKeyPad + mac.digest(iKeyPad + message))
}

@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
fun hmacSha1(key: ByteArray, message: ByteArray): String {
    return hmac(key, message, SHA1(), blockSize = 64)
}

@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
fun hmacMd5(key: ByteArray, message: ByteArray): String {
    return hmac(key, message, MD5(), blockSize = 64)
}
