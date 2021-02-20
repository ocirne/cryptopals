package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics
import kotlin.experimental.xor

class Challenge4 {

    private fun decrypt(secret: String): String? {
        val s = Basics.decodeHexString(secret)
        val mostCommonByte = Basics.mostCommon(s)
        val key = mostCommonByte xor ' '.toByte()
        val plainBa = Basics.xorSingle(s, key)
        return if (Basics.isPlausiblePlainText(plainBa, 0.33, 0.1)) String(plainBa) else null
    }

    fun run(secrets: List<String>): String {
        return secrets.mapNotNull { secret -> decrypt(secret) }.first()
    }
}
