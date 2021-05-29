package io.github.ocirne.cryptopals.set2


import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import io.github.ocirne.cryptopals.Basics.decodeFromBase64
import io.github.ocirne.cryptopals.crypto.AES
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge10Test {

    companion object {
        private val content = this::class.java.classLoader.getResource("set2/10.txt")!!.readText()
        private val key = "YELLOW SUBMARINE".toByteArray()
        private val iv = 0x00.toByte().repeat(16)
    }

    @Test
    fun `can decrypt example`() {
        val aesCbc = AES.CBC(key, iv)
        val pt = String(aesCbc.decrypt(decodeFromBase64(content)))
        pt.take(33) shouldBe "I'm back and I'm ringin' the bell"
    }
}
