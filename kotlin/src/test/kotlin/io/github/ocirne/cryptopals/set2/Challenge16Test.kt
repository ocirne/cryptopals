package io.github.ocirne.cryptopals.set2

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

internal class Challenge16Test {

    private val oracle = Challenge16.CbcPrefixSuffix()

    private val judge = Challenge16.Judge(oracle)

    private val attacker = Challenge16.Attacker()

    @Test
    fun `can break challenge 16`() {
        val ciphertext = oracle.encrypt(";admin=true;".toByteArray())
        judge.isBroken(ciphertext) shouldBe false
        val modified = attacker.modify(ciphertext)
        judge.isBroken(modified) shouldBe true
    }
}
