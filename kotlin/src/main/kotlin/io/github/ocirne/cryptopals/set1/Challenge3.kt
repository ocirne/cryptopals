package io.github.ocirne.cryptopals.set1

import com.google.common.io.BaseEncoding
import kotlin.experimental.xor

class Challenge3 {

    private fun fixedXorSingleByte(secret: String, key: Byte): ByteArray {
        val sBa = BaseEncoding.base16().decode(secret.toUpperCase())
        return sBa.map { c -> c.xor(key) }.toByteArray()
    }

    fun decrypt(secret: String): String {
        val sBa = BaseEncoding.base16().decode(secret.toUpperCase())
        val counts = sBa.toTypedArray().groupingBy { it }.eachCount()
        val mostCommonByte = counts.maxByOrNull { it.value }!!.key
        val key = mostCommonByte.xor(' '.toByte())
        val plainBa = fixedXorSingleByte(secret, key)
        return String(plainBa)
    }
}
