package io.github.ocirne.cryptopals

import com.google.common.io.BaseEncoding
import io.github.ocirne.cryptopals.Basics.Extensions.cycle
import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import java.util.*
import kotlin.experimental.xor

object Basics {

    object Extensions {
        fun Byte.repeat(n: Int) = IntRange(1, n).map { this }.toByteArray()

        fun ByteArray.cycle() = generateSequence(0) { (it + 1) % this.size }.map { this[it] }.asIterable()

        fun ByteArray.mostCommon() = mostCommon(this.asList())
    }

    fun decodeHexString(hexString: String): ByteArray {
        val correctedHexString = if (hexString.length % 2 != 0) hexString.dropLast(1) else hexString
        return BaseEncoding.base16().decode(correctedHexString.uppercase(Locale.getDefault()))
    }

    fun encodeHexString(byteArray: ByteArray): String {
        return BaseEncoding.base16().encode(byteArray).lowercase(Locale.getDefault())
    }

    fun encodeToBase64(byteArray: ByteArray): String {
        return Base64.getEncoder().encodeToString(byteArray)
    }

    fun decodeFromBase64(text: String): ByteArray {
        val base64String = text.filter { c -> !c.isWhitespace() }
        return Base64.getDecoder().decode(base64String)
    }

    private fun xor(byteArray: ByteArray, y: Iterable<Byte>): ByteArray {
        return byteArray.zip(y).map { (a, b) -> a xor b }.toByteArray()
    }

    fun xor(byteArray: ByteArray, y: ByteArray): ByteArray {
        return xor(byteArray, y.asIterable())
    }

    fun xorCycle(byteArray: ByteArray, key: ByteArray): ByteArray {
        return xor(byteArray, key.cycle())
    }

    fun xorSingle(byteArray: ByteArray, key: Byte): ByteArray {
        return xorCycle(byteArray, byteArrayOf(key))
    }

    fun <T> mostCommon(list: List<T>): T {
        val counts = list.groupingBy { it }.eachCount()
        return counts.maxByOrNull { it.value }!!.key
    }

    fun isPlausiblePlainText(plain: ByteArray, minRatioLowerCase: Double, minRatioBlanks: Double): Boolean {
        val minAbsLowerCase = minRatioLowerCase * plain.size
        val minAbsBlanks = minRatioBlanks * plain.size
        val absLowerCase = plain.count { c -> c in 'a'.code.toByte()..'z'.code.toByte() }
        val absBlanks = plain.count { c -> c == ' '.code.toByte() }
        return minAbsLowerCase <= absLowerCase && minAbsBlanks <= absBlanks
    }

    fun hammingDistance(t1: ByteArray, t2: ByteArray): Int {
        return t1.zip(t2).map { (x, y) -> x xor y }.sumOf { x -> x.countOneBits() }
    }

    fun calcScore(text: ByteArray): Float {
        // 'A' - 'Z'
        val totalUpper = text.filter { c -> c in 65..90 }.count()
        // 'a' - 'z'
        val totalLower = text.filter { c -> c in 97..122 }.count()
        // ' '
        val totalBlank = text.filter { s -> s == 32.toByte() }.count()
        return (totalUpper + totalLower + totalBlank).toFloat() / text.size
    }

    fun padding(plaintext: ByteArray, blockSize: Int=16): ByteArray {
        val padLength = (blockSize - plaintext.size % blockSize)
        if (padLength == 0) {
//            padLength = blockSize
            throw IllegalStateException("should not be reachable")
        }
        return plaintext + byteArrayOf(padLength.toByte()).cycle().take(padLength)
    }

    class InvalidPaddingException(): Exception("Invalid padding")

    fun stripPadding(plaintext: ByteArray): ByteArray {
        val c = plaintext[-1]
        val t = plaintext.sliceArray(0..plaintext.size-c)
        val s = plaintext.sliceArray(plaintext.size-c until plaintext.size)
        if (s.contentEquals(c.repeat(s.size)) && (t.isNotEmpty() || t[-1] != c)) {
            return t
        }
        throw InvalidPaddingException ()
    }
}
