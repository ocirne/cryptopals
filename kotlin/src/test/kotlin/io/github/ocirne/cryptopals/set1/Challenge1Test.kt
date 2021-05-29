package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics.decodeHexString
import io.github.ocirne.cryptopals.Basics.encodeToBase64
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge1Test {

    @Test
    fun `Convert hex to base64`() {
        val hexString =
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        val base64String = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

        val ba = decodeHexString(hexString)
        encodeToBase64(ba) shouldBe base64String
    }
}
