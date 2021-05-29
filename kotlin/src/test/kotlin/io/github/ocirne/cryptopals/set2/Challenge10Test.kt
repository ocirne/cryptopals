package io.github.ocirne.cryptopals.set2


import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge10Test {

    companion object {
        private val content = this::class.java.classLoader.getResource("set2/10.txt")!!.readText()
        private const val key = "YELLOW SUBMARINE"
        private val iv = 0x00.toByte().repeat(16)
    }

    @Test
    fun `can decrypt example`() {
        challenge10(content, key, iv).take(33) shouldBe "I'm back and I'm ringin' the bell"
    }
}
