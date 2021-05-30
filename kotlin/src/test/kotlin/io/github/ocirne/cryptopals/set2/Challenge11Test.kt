package io.github.ocirne.cryptopals.set2

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge11Test {

    @Test
    fun `can detect ecb mode`() {
        val oracle = Challenge11Oracle("ECB")
        detectMode(oracle) shouldBe "ECB"
    }

    @Test
    fun `can detect cbc mode`() {
        val oracle = Challenge11Oracle("CBC")
        detectMode(oracle) shouldBe "CBC"
    }
}
