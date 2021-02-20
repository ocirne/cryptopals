package io.github.ocirne.cryptopals.set1

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge1Test {

    @Test
    fun `Convert hex to base64`() {
        val hexString =
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        val base64String = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

        Challenge1().hexToBase64(hexString) shouldBe base64String
    }
}