package io.github.ocirne.cryptopals.set3

import io.github.ocirne.cryptopals.set3.Challenge21.MersenneTwister
import kotlin.random.Random

class Challenge22 {

    class RandomNumberOracle {

        private var seed = 0u

        private fun waitRandom() {
            // wait between 1 and 10 seconds - for unit tests enough
            Thread.sleep(Random.nextLong(1_000, 10_000))
        }

        fun totallyRandomNumber(): UInt {
            waitRandom()
            seed = System.currentTimeMillis().toUInt() / 1000u
            val mt = MersenneTwister(seed)
            waitRandom()
            return mt.next()
        }

        fun hint(): UInt {
            return seed
        }
    }

    class Attacker {
        fun recoverSeed(prn: UInt, now: UInt = System.currentTimeMillis().toUInt() / 1000u): UInt {
            for (ut in now downTo now - 3600u) {
                if (MersenneTwister(ut).next() == prn) {
                    return ut
                }
            }
            throw IllegalStateException()
        }
    }
}
