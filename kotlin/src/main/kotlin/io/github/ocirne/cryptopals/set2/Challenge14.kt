package io.github.ocirne.cryptopals.set2

import io.github.ocirne.cryptopals.Basics
import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import io.github.ocirne.cryptopals.Oracle
import io.github.ocirne.cryptopals.crypto.AES
import kotlin.random.Random

class Challenge14 {

    class PrefixSuffixEcbOracle(unknownString: String): Oracle {

        private val target = Basics.decodeFromBase64(unknownString)
        private val key = Random.nextBytes(AES.BLOCK_SIZE)
        private val aes = AES.ECB(key)
        private val lengthRandomPrefix = Random.nextInt(1,100)
        private val randomPrefix = Random.nextBytes(lengthRandomPrefix)

        override fun encrypt(attackerControlled: ByteArray): ByteArray {
            return aes.encrypt(randomPrefix + attackerControlled + target)
        }
    }

    class Attacker(val oracle: Oracle) {

        private fun lookup(skip: Int, injectLength: Int, knownSecret: ByteArray, knownContent: ByteArray): Byte? {
            return IntRange(0, 255)
                .map(Int::toByte)
                .firstOrNull { b ->
                    val secret = oracle.encrypt(0x00.toByte().repeat(injectLength) + knownContent + byteArrayOf(b))
                    secret.drop(skip).take(AES.BLOCK_SIZE) == knownSecret.drop(skip).take(AES.BLOCK_SIZE)
                }
        }

        private fun findIgnorablePart(): Int {
            val blankBlocks = 0x00.toByte().repeat(3 * AES.BLOCK_SIZE)
            val secret = oracle.encrypt(blankBlocks)
            val countIgnoreBlocks = secret.asIterable()
                .chunked(AES.BLOCK_SIZE)
                .zipWithNext()
                .indexOfFirst { (a, b) -> a == b }
            // TODO Magic eight
            return (countIgnoreBlocks + 8) * AES.BLOCK_SIZE
        }

        fun crack(): String {
            val skip = findIgnorablePart()
            var known = byteArrayOf()
            for (i in 159 downTo -100) {
                val secret = oracle.encrypt(0x00.toByte().repeat(i))
                val b = lookup(skip, i, secret, known) ?: return String(known)
                if (b != 0.toByte()) {
                    known += b
                }
            }
            return String(known)
        }
    }
}
