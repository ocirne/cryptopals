package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics.encodeHexString
import io.github.ocirne.cryptopals.Basics.xorCycle
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge5Test {

    @Test
    fun `Implement repeating-key XOR`() {
        val plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        val key = "ICE"
        val secret = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
                "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        val ct = xorCycle(plain.toByteArray(), key.toByteArray())
        encodeHexString(ct) shouldBe secret
    }
}
