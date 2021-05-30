package io.github.ocirne.cryptopals.set2

import io.github.ocirne.cryptopals.Basics.Extensions.padding
import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge9Test {

    @Test
    fun `can pad example message`() {
        val padded = wrapPadding("YELLOW SUBMARINE", 20)
        padded shouldBe "YELLOW SUBMARINE\u0004\u0004\u0004\u0004"
        padded.length shouldBe 20
    }

    @Test
    fun `can pad example with another blocksize`() {
        val padded = wrapPadding("YELLOW SUBMARINE", 18)
        padded shouldBe "YELLOW SUBMARINE\u0002\u0002"
        padded.length shouldBe 18
    }

    @Test
    fun `can pad with message length exactly block size`() {
        val padded = wrapPadding("FOO", 3)
        padded shouldBe "FOO\u0003\u0003\u0003"
        padded.length shouldBe 6
    }

    @Test
    fun `can pad example from challenge 15`() {
        val padded = wrapPadding("ICE ICE BABY", 16)
        padded shouldBe "ICE ICE BABY\u0004\u0004\u0004\u0004"
        padded.length shouldBe 16
    }

    @Test
    fun `can pad example from challenge 15b`() {
        val padded = wrapPadding("ICE ICE BABY", 20)
        padded shouldBe "ICE ICE BABY\u0008\u0008\u0008\u0008\u0008\u0008\u0008\u0008"
        padded.length shouldBe 20
    }

    private fun wrapPadding(message: String, blockSize: Int): String {
        return message.toByteArray().padding(blockSize).decodeToString()
    }
}
