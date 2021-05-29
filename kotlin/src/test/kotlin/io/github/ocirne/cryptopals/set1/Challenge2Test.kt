package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics.decodeHexString
import io.github.ocirne.cryptopals.Basics.encodeHexString
import io.github.ocirne.cryptopals.Basics.xor
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge2Test {

    @Test
    fun `Fixed XOR`() {
        val t = decodeHexString("1c0111001f010100061a024b53535009181c")
        val s = decodeHexString("686974207468652062756c6c277320657965")
        val c = xor(t, s)
        encodeHexString(c) shouldBe "746865206b696420646f6e277420706c6179"
    }
}
