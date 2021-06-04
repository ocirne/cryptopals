package io.github.ocirne.cryptopals.set2

import Challenge12
import Challenge12Oracle
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge12Test {

    private val unknownString = """
        Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK
        """

    private val oracle = Challenge12Oracle(unknownString)

    private val challenge12 = Challenge12(oracle)

    @Test
    fun `can discover block size`() {
        challenge12.discoverBlockSize() shouldBe 16
    }

    @Test
    fun `can discover mode`() {
        challenge12.discoverMode() shouldBe "ECB"
    }

    @Test
    fun `can crack with padding attack`() {
        challenge12.crack().take(6) shouldBe "Rollin"
    }
}
