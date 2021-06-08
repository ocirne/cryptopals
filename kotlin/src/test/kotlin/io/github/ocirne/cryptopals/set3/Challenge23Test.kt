package io.github.ocirne.cryptopals.set3

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test
import kotlin.random.Random


internal class Challenge23Test {

    private val attacker = Challenge23.Attacker()

    @Test
    fun `can untemper pseudo random number`() {
        val mt = Challenge21.MersenneTwister(0u)
        val prn = mt.tempering(42u)
        prn shouldBe 168040107u
        attacker.untempering(prn) shouldBe 42u
    }

    @Test
    fun `can replicate random generator from stream`() {
        val seed = Random.nextInt().toUInt()
        val origMt = Challenge21.MersenneTwister(seed)
        val copyMt = attacker.replicateStream(origMt)

        copyMt.take(624) shouldBe origMt.take(624)
    }
}
