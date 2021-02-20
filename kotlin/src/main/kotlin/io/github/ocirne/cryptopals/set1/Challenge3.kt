package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics
import kotlin.experimental.xor

class Challenge3 {

    fun run(secret: String): String {
        val s = Basics.decodeHexString(secret)
        val mostCommonByte = Basics.mostCommon(s)
        val key = mostCommonByte xor ' '.toByte()
        val plainBa = Basics.xorSingle(s, key)
        return String(plainBa)
    }
}
