package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics.decodeFromBase64
import io.github.ocirne.cryptopals.crypto.AES
import io.kotest.matchers.string.shouldStartWith
import org.junit.jupiter.api.Test

internal class Challenge7Test {

    @Test
    fun `AES in ECB mode`() {
        val key = "YELLOW SUBMARINE".toByteArray()
        val content = this::class.java.classLoader.getResource("set1/7.txt")!!.readText()
        val aesEcb = AES.ECB(key)
        val pt = String(aesEcb.decrypt(decodeFromBase64(content)))
        pt shouldStartWith "I'm back and I'm ringin' the bell"
    }
}
