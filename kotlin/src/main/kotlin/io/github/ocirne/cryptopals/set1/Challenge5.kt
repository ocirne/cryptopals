package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics

class Challenge5 {

    fun run(plain: String, key: String): String {
        val p = plain.toByteArray()
        val k = key.toByteArray()
        val c = Basics.xorCycle(p, k)
        return Basics.encodeHexString(c)
    }
}
