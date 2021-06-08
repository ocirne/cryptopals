package io.github.ocirne.cryptopals.set3

import io.github.ocirne.cryptopals.set3.Challenge21.MersenneTwister

class Challenge23 {

    class Attacker {

        /** see https://occasionallycogent.com/inverting_the_mersenne_temper/index.html */
        fun untempering(p: UInt): UInt {
            var e = p xor (p shr 18)
            e = e xor ((e shl 15) and 0xEFC6_0000u)
            e = e xor ((e shl 7) and 0x0000_1680u)
            e = e xor ((e shl 7) and 0x000C_4000u)
            e = e xor ((e shl 7) and 0x0D20_0000u)
            e = e xor ((e shl 7) and 0x9000_0000u)
            e = e xor ((e shr 11) and 0xFFC0_0000u)
            e = e xor ((e shr 11) and 0x003F_F800u)
            e = e xor ((e shr 11) and 0x0000_07FFu)
            return e
        }

        fun replicateStream(origMt: MersenneTwister): MersenneTwister {
            val copyMt = MersenneTwister(0u)
            origMt.take(625).forEachIndexed { i, p ->
                copyMt.y[i] = untempering(p)
            }
            return copyMt
        }
    }
}
