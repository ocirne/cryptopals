package io.github.ocirne.cryptopals.set1

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge4Test {

    @Test
    fun `Detect single-character XOR`() {
        val secrets = this::class.java.classLoader.getResourceAsStream("set1/4.txt")!!.bufferedReader().readLines()
        val plain = "Now that the party is jumping\n"
        Challenge4().decrypt(secrets) shouldBe plain
    }
}
