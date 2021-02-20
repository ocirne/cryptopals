package io.github.ocirne.cryptopals.set1

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge2Test {

    @Test
    fun `Fixed XOR`() {
        val t = "1c0111001f010100061a024b53535009181c"
        val s = "686974207468652062756c6c277320657965"
        val c = "746865206b696420646f6e277420706c6179"
        Challenge2().run(t, s) shouldBe c
    }
}
