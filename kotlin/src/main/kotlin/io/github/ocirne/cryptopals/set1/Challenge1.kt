package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics

class Challenge1 {

    fun run(hexString: String): String {
        val byteArray = Basics.decodeHexString(hexString)
        return Basics.encodeToBase64(byteArray)
    }
}