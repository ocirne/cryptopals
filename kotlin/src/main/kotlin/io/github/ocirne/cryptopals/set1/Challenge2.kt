package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics

class Challenge2 {

    fun run(t: String, s: String): String {
        val x = Basics.decodeHexString(t)
        val y = Basics.decodeHexString(s)
        val c = Basics.xor(x, y)
        return Basics.encodeHexString(c)
    }
}
