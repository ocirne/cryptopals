package io.github.ocirne.cryptopals.set3

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test


internal class Challenge21Test {

    private val seed = 1131464071u

    private val mersenneTwister = Challenge21.MersenneTwister(seed)

    /**
     * test vectors see https://gist.github.com/mimoo/8e5d80a2e236b8b6f5ed
     */
    @Test
    fun `can reproduce test vector`() {
        mersenneTwister.take(10) shouldBe listOf(
            3521569528u,
            1101990581u,
            1076301704u,
            2948418163u,
            3792022443u,
            2697495705u,
            2002445460u,
            502890592u,
            3431775349u,
            1040222146u
        )
        mersenneTwister.next() shouldBe 3582980688u
    }
}
