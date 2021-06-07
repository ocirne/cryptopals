package io.github.ocirne.cryptopals.set2

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge11Test {

    @Test
    fun `can detect ecb mode`() {
        val oracle = Challenge11.RandomAesModeOracle("ECB")
        val attacker = Challenge11.Attacker(oracle)
        attacker.detectMode() shouldBe "ECB"
    }

    @Test
    fun `can detect cbc mode`() {
        val oracle = Challenge11.RandomAesModeOracle("CBC")
        val attacker = Challenge11.Attacker(oracle)
        attacker.detectMode() shouldBe "CBC"
    }
}
