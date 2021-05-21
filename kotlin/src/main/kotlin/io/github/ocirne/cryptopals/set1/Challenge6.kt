package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics
import io.github.ocirne.cryptopals.Basics.Extensions.mostCommon
import io.github.ocirne.cryptopals.Basics.hammingDistance
import kotlin.experimental.xor

import io.github.ocirne.cryptopals.Basics.mostCommon

class Challenge6(text: String) {

    private val content: ByteArray = Basics.decodeFromBase64(text)

    fun decrypt(key: String): String {
        val k = key.toByteArray()
        val pt = Basics.xorCycle(content, k)
        return String(pt)
    }

    fun cheapFactor(n: Int): List<Int> {
        val result = mutableListOf<Int>()
        var x = n
        var i = 2
        while (i <= x) {
            if (x % i == 0) {
                result.add(i)
                while (x % i == 0) {
                    x /= i
                }
            }
            i += 1
        }
        return result
    }

    private fun checkKeySize(keySize: Int): List<Int> {
        val blocks = content.asIterable().chunked(keySize).take(4).map { b -> b.toByteArray() }
        val distances = mutableListOf<Int>()
        for (block1 in blocks) {
            for (block2 in blocks) {
                if (block1.hashCode() < block2.hashCode()) {
                    distances.add(hammingDistance(block1, block2))
                }
            }
        }
        return if (distances.average() / keySize < 3) cheapFactor(keySize) else listOf()
    }

    fun getCommonDistance(): Int {
        val distances = IntRange(2, 100).flatMap { keySize -> checkKeySize(keySize) }
        return mostCommon(distances)
    }

    private fun transpose(keySize: Int): List<ByteArray> {
        return IntRange(0, keySize - 1).map { i ->
            content.filterIndexed { index, _ -> index % keySize == i }.toByteArray()
        }
    }

    private fun findKeyLetter(transposed_block: ByteArray): Byte {
        val mostCommonByte = transposed_block.mostCommon()
        return mostCommonByte xor ' '.code.toByte()
    }

    fun findKey(keySize: Int): String {
        return String(transpose(keySize).map { tb -> findKeyLetter(tb) }.toByteArray())
    }
}
