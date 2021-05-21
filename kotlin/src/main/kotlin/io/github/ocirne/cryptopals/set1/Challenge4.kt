package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics
import io.github.ocirne.cryptopals.Basics.Extensions.mostCommon
import kotlin.experimental.xor

class Challenge4 {

    private fun decrypt(secret: String): String? {
        val ct = Basics.decodeHexString(secret)
        val mostCommonByte = ct.mostCommon()
        val key = mostCommonByte xor ' '.code.toByte()
        val pt = Basics.xorSingle(ct, key)
        return if (Basics.isPlausiblePlainText(pt, 0.33, 0.1))
            String(pt)
        else
            null
    }

    fun run(secrets: List<String>): String {
        return secrets.mapNotNull { secret -> decrypt(secret) }.first()
    }
}
