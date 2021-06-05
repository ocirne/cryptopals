package io.github.ocirne.cryptopals.set2

import io.github.ocirne.cryptopals.Basics
import io.github.ocirne.cryptopals.Basics.stripPadding
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge15Test {

    @Test
    fun `can strip padding example`() {
        wrapStripPadding("ICE ICE BABY\u0004\u0004\u0004\u0004") shouldBe "ICE ICE BABY"
    }

    @Test
    fun `reject padding too long`() {
        shouldThrow<Basics.InvalidPaddingException> {
            wrapStripPadding("ICE ICE BABY\u0004\u0004\u0004\u0004\u0004")
        }
    }

    @Test
    fun `reject padding wrong value`() {
        shouldThrow<Basics.InvalidPaddingException> {
            wrapStripPadding("ICE ICE BABY\u0005\u0005\u0005\u0005")
        }
    }

    @Test
    fun `reject inconsistent padding`() {
        shouldThrow<Basics.InvalidPaddingException> {
            wrapStripPadding("ICE ICE BABY\u0001\u0002\u0003\u0004")
        }
    }

    @Test
    fun `can strip irregular padding block size 20`() {
        wrapStripPadding("YELLOW SUBMARINE\u0004\u0004\u0004\u0004") shouldBe "YELLOW SUBMARINE"

    }

    @Test
    fun `can strip irregular padding block size 18`() {
        wrapStripPadding("YELLOW SUBMARINE\u0002\u0002") shouldBe "YELLOW SUBMARINE"
    }

    @Test
    fun `can strip padding with exact block size`() {
        wrapStripPadding("FOO\u0003\u0003\u0003") shouldBe "FOO"
    }

    private fun wrapStripPadding(s: String): String {
        return String(stripPadding(s.toByteArray()))
    }
}
