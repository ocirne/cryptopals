package io.github.ocirne.cryptopals.set1

import com.google.common.io.BaseEncoding
import kotlin.experimental.xor

class Challenge4 {

    private fun fromHex(paramHexString: String): ByteArray {
        val hexString = if (paramHexString.length % 2 != 0) paramHexString.dropLast(1) else paramHexString
        return BaseEncoding.base16().decode(hexString.toUpperCase())
    }

    private fun fixedXorSingleByte(secret: String, key: Byte): ByteArray {
        val sBa = BaseEncoding.base16().decode(secret.toUpperCase())
        return sBa.map { c -> c.xor(key) }.toByteArray()
    }

    private fun checkPlain(plain: ByteArray): Boolean {
        val lowerLetters = plain.count { c -> c in 'a'.toByte()..'z'.toByte() }
        val blanks = plain.count { c -> c == ' '.toByte() }
        return lowerLetters >= 20 && blanks >= 5
    }

    private fun decrypt(secret: String): String? {
        val sBa = fromHex(secret)
        val counts = sBa.toTypedArray().groupingBy { it }.eachCount()
        val mostCommonByte = counts.maxByOrNull { it.value }!!.key
        val key = mostCommonByte.xor(' '.toByte())
        val plainBa = fixedXorSingleByte(secret, key)
        if (checkPlain(plainBa)) {
            return String(plainBa)
        }
        return null
    }

    fun decrypt(secrets: List<String>): String {
        return secrets.mapNotNull { secret -> decrypt(secret) }.first()
    }
}
