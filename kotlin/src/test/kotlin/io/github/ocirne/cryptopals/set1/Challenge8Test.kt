package io.github.ocirne.cryptopals.set1

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge8Test {

    @Test
    fun `Detect AES in ECB mode`() {
        val content = this::class.java.classLoader.getResourceAsStream("set1/8.txt")!!.bufferedReader().readLines()

        Challenge8().run(content) shouldBe 133
    }
}
