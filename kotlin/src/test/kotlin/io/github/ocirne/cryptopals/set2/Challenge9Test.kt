package io.github.ocirne.cryptopals.set2

import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge9Test {

    @Test
    fun `can pad example message`() {
        val padded = challenge9("YELLOW SUBMARINE", 20)
        padded shouldBe "YELLOW SUBMARINE" + String(0x04.toByte().repeat(4))
        padded.length shouldBe 20
    }

    @Test
    fun `can pad example with another blocksize`() {
        val padded = challenge9("YELLOW SUBMARINE", 18)
        padded shouldBe "YELLOW SUBMARINE" + String(0x02.toByte().repeat(2))
        padded.length shouldBe 18
    }

    @Test
    fun `can pad with message length exactly block size`() {
        val padded = challenge9("FOO", 3)
        padded shouldBe "FOO" + String(0x03.toByte().repeat(3))
        padded.length shouldBe 6
    }
}
