package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics
import io.github.ocirne.cryptopals.Basics.Extensions.mostCommon
import kotlin.experimental.xor

class Challenge3 {

    fun run(secret: String): String {
        val ct = Basics.decodeHexString(secret)
        val mostCommonByte = ct.mostCommon()
        val key = mostCommonByte xor ' '.toByte()
        val pt = Basics.xorSingle(ct, key)
        return String(pt)
    }
}
