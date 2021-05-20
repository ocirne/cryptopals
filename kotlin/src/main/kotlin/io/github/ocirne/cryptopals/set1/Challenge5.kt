package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics

class Challenge5 {

    fun run(plain: String, key: String): String {
        val pt = plain.toByteArray()
        val k = key.toByteArray()
        val ct = Basics.xorCycle(pt, k)
        return Basics.encodeHexString(ct)
    }
}
