package io.github.ocirne.cryptopals.set3

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test


internal class Challenge22Test {

    private val attacker = Challenge22.Attacker()

    @Test
    fun `can recover seed for long time range`() {
        val seed = 1619795688u
        val prn = 3339454654u
        val now = 1619796899u
        attacker.recoverSeed(prn, now) shouldBe seed
    }

    @Test
    fun `can recover seed for short time range`() {
        val oracle = Challenge22.RandomNumberOracle()
        val prn = oracle.totallyRandomNumber()
        attacker.recoverSeed(prn) shouldBe oracle.hint()
    }
}
