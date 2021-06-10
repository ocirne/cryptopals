package io.github.ocirne.cryptopals.set3

import io.github.ocirne.cryptopals.Basics.InvalidPaddingException
import io.github.ocirne.cryptopals.Basics.padding
import io.github.ocirne.cryptopals.Basics.stripPadding
import io.github.ocirne.cryptopals.Basics.xor
import io.github.ocirne.cryptopals.Oracle
import io.github.ocirne.cryptopals.set3.Challenge21.MersenneTwister
import kotlin.random.Random
import kotlin.random.nextUInt

class Challenge24 {

    class MersenneTwisterStreamCipher(private val seed: UInt): Oracle {

        private fun keyStream(mt: MersenneTwister, count: Int): ByteArray {
            return mt.take(count).map { k -> (k % 256u).toByte() }.toByteArray()
        }

        fun token(): ByteArray {
            val mt = MersenneTwister(seed)
            return keyStream(mt, 16)
        }

        override fun encrypt(pt: ByteArray): ByteArray {
            val mt = MersenneTwister(seed)
            val ppt = padding(pt, 4)
            return xor(ppt, keyStream(mt, ppt.size))
        }

        override fun decrypt(ct: ByteArray): ByteArray {
            val mt = MersenneTwister(seed)
            val ppt = xor(ct, keyStream(mt, ct.size))
            return stripPadding(ppt)
        }
    }

    class RandomPrefixOracle: Oracle {

        val seed : UInt = Random.nextUInt()

        private val mtsc = MersenneTwisterStreamCipher(seed)

        override fun encrypt(pt: ByteArray): ByteArray {
            val prefix = Random.nextBytes(Random.nextInt(100))
            return mtsc.encrypt(prefix + pt)
        }
    }

    class PasswordResetTokenOracle: Oracle {

        // create a password token randomly in the last hour
        val seed: UInt = (System.currentTimeMillis() / 1000).toUInt() - Random.nextUInt(3600u)

        override fun encrypt(pt: ByteArray): ByteArray {
            throw UnsupportedOperationException()
        }

        fun generatePasswordToken(): ByteArray {
            val mtsc = MersenneTwisterStreamCipher(seed)
            return mtsc.token()
        }
    }

    class Attacker {
        fun recoverSeed(cipherText: ByteArray, known: ByteArray): UInt {
            val sKnown = String(known)
            for (seed in UInt.MAX_VALUE downTo 0u) {
                if (seed % 1000u == 0u) {
                    println(seed)
                }
                val mt = MersenneTwisterStreamCipher(seed)
                try {
                    val cpt = mt.decrypt(cipherText)
                    if (String(cpt).contains(sKnown)) {
                        return seed
                    }
                } catch (e: InvalidPaddingException) {
                    // expected for most wrong seeds
                }
            }
            throw IllegalStateException()
        }

        fun recoverTimestamp(passwordToken: ByteArray): UInt {
            val currentTime = (System.currentTimeMillis() / 1000).toUInt()
            for (ut in currentTime downTo currentTime - 3700u) {
                if (MersenneTwisterStreamCipher(ut).token().contentEquals(passwordToken)) {
                    return ut
                }
            }
            throw IllegalStateException()
        }
    }
}


