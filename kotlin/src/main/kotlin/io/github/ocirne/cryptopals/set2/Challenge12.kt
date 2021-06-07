package io.github.ocirne.cryptopals.set2

import io.github.ocirne.cryptopals.Basics
import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import io.github.ocirne.cryptopals.Basics.padding
import io.github.ocirne.cryptopals.Oracle
import io.github.ocirne.cryptopals.crypto.AES
import kotlin.random.Random

class Challenge12 {

    class SuffixEcbOracle(private val unknownString: String): Oracle {

        val key = Random.nextBytes(AES.BLOCK_SIZE)
        val aes = AES.ECB(key)

        override fun encrypt(pt: ByteArray): ByteArray {
            val padded = padding(pt + Basics.decodeFromBase64(unknownString))
            return aes.encrypt(padded)
        }
    }

    class Attacker(val oracle: Oracle) {

        private fun discoverNextHop(oldBlockSize: Int): Int {
            return IntRange(1, 100)
                .map { i -> oracle.encrypt(0x00.toByte().repeat(i)).size }
                .first { newBlockSize -> oldBlockSize < newBlockSize }
        }

        fun discoverBlockSize(): Int {
            val firstBlockSize = oracle.encrypt(byteArrayOf()).size
            val hop1 = discoverNextHop(firstBlockSize)
            val hop2 = discoverNextHop(hop1 + 1)
            return hop2 - hop1
        }

        fun discoverMode(): String {
            val secret = oracle.encrypt(0x00.toByte().repeat(32))
            return if (secret.slice(0..15) == secret.slice(16..31)) "ECB" else "CBC"
        }

        private fun lookup(i: Int, knownSecret: ByteArray, knownContent: ByteArray): Byte? {
            return IntRange(0, 255)
                .map(Int::toByte)
                .firstOrNull { b ->
                    val secret = oracle.encrypt(0x00.toByte().repeat(i) + knownContent + byteArrayOf(b))
                    secret.sliceArray(0..159).contentEquals(knownSecret)
                }
        }

        fun crack(): String {
            var known = byteArrayOf()
            for (i in 159 downTo 0) {
                val secret = oracle.encrypt(0x00.toByte().repeat(i))
                known += lookup(i, secret.sliceArray(0..159), known) ?: return String(known)
            }
            throw IllegalStateException()
        }
    }
}
