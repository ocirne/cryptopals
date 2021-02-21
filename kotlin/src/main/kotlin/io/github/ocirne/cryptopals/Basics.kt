package io.github.ocirne.cryptopals

import com.google.common.io.BaseEncoding
import java.util.Base64
import kotlin.experimental.xor

object Basics {

    private fun ByteArray.cycle() =
        generateSequence(0) { (it + 1) % this.size }.map { this[it] }.asIterable()

    fun decodeHexString(hexString: String): ByteArray {
        val correctedHexString = if (hexString.length % 2 != 0) hexString.dropLast(1) else hexString
        return BaseEncoding.base16().decode(correctedHexString.toUpperCase())
    }

    fun encodeHexString(byteArray: ByteArray): String {
        return BaseEncoding.base16().encode(byteArray).toLowerCase()
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

    fun mostCommon(byteArray: ByteArray): Byte {
        val counts = byteArray.toTypedArray().groupingBy { it }.eachCount()
        return counts.maxByOrNull { it.value }!!.key
    }

    fun isPlausiblePlainText(plain: ByteArray, minRatioLowerCase: Double, minRatioBlanks: Double): Boolean {
        val minAbsLowerCase = minRatioLowerCase * plain.size
        val minAbsBlanks = minRatioBlanks * plain.size
        val absLowerCase = plain.count { c -> c in 'a'.toByte()..'z'.toByte() }
        val absBlanks = plain.count { c -> c == ' '.toByte() }
        return minAbsLowerCase <= absLowerCase && minAbsBlanks <= absBlanks
    }
}
