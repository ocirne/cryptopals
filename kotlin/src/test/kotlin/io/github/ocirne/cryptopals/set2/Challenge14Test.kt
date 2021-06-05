package io.github.ocirne.cryptopals.set2

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge14Test {

    private val unknownString = """
        Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK
        """

    private val oracle = Challenge14Oracle(unknownString)

    private val challenge14 = Challenge14(oracle)

    @Test
    fun `can crack with padding attack`() {
        challenge14.crack().take(6) shouldBe "Rollin"
    }
}
