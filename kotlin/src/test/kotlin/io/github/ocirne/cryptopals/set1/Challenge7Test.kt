package io.github.ocirne.cryptopals.set1

import io.kotest.matchers.string.shouldStartWith
import org.junit.jupiter.api.Test

internal class Challenge7Test {

    @Test
    fun `AES in ECB mode`() {
        val key = "YELLOW SUBMARINE"
        val content = this::class.java.classLoader.getResource("set1/7.txt")!!.readText()

        Challenge7().run(content, key) shouldStartWith "I'm back and I'm ringin' the bell"
    }
}
