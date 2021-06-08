package io.github.ocirne.cryptopals.set3

class Challenge21 {

    class MersenneTwister(seed: UInt) {

        private val y = ArrayDeque<UInt>()

        init {
            var x = seed
            y.addLast(x)
            for (i in 1u..624u) {
                x = (1812433253u * (x xor (x shr 30)) + i) and 0xFFFF_FFFFu
                y.addLast(x)
            }
        }

        private fun tempering(p: UInt): UInt {
            var e = p
            e = e xor (e shr 11)
            e = e xor ((e shl 7) and 0x9D2C_5680u)
            e = e xor ((e shl 15) and 0xEFC6_0000u)
            return e xor (e shr 18)
        }

        private val generator = sequence {
            while (true) {
                val h = y[0] - (y[0] and 0x7FFF_FFFFu) + (y[1] and 0x7FFF_FFFFu)
                val v = y[397] xor (h shr 1) xor ((h and 1u) * 0x9908_B0DFu)
                y.addLast(v)
                y.removeFirst()
                yield(tempering(v))
            }
        }

        fun take(count: Int = 1): List<UInt> {
            return generator.take(count).toList()
        }

        fun next(): UInt {
            return generator.first()
        }
    }
}
