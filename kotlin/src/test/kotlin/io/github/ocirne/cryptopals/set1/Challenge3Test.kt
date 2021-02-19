package io.github.ocirne.cryptopals.set1

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge3Test {

    @Test
    fun `can decrypt secret`() {
        val secret = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        val plain = "Cooking MC's like a pound of bacon"
        Challenge3().decrypt(secret) shouldBe plain
    }
}
