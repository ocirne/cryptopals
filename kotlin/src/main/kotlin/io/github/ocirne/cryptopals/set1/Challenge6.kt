package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics
import kotlin.experimental.xor

class Challenge6(text: String) {

    private val content: ByteArray = Basics.decodeFromBase64(text)

    fun decrypt(key: String): String {
        val k = key.toByteArray()
        val p = Basics.xorCycle(content, k)
        return String(p)
    }

    fun hammingDistance(t1: ByteArray, t2: ByteArray): Int {
        return t1.zip(t2)
            .map { (x, y) -> x xor y }
            .map { x -> x.toString(2).count { c -> c == '1' } }
            .sum()
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

    fun checkKeySize(keySize: Int): List<Int> {
        val blocks = content.asIterable().chunked(keySize)
        val normalizedMeanDistance = blocks.pairs
    }

    fun getCommonDistance(): Int {
        val distances = IntRange(2, 100).flatMap { keySize -> checkKeySize(keySize) }.toByteArray()
        return Basics.mostCommon(distances)

        distances = []
        for key_size in range(2, 100):
            blocks = (cipher[i * key_size:(i + 1) * key_size] for i in range(4))
            normalized_mean_distance = \
                mean(hamming_distance(block1, block2) / key_size for block1, block2 in combinations(blocks, 2))
            if normalized_mean_distance < 3:
                distances.extend(factor(key_size))
        return Counter(distances).most_common(1)[0][0]
        */
    }

    private fun transpose(keySize: Int): List<ByteArray> {
        return IntRange(0, keySize - 1).map { i ->
            content.filterIndexed { index, _ -> index % keySize == i }.toByteArray()
        }
    }

    private fun findKeyLetter(transposed_block: ByteArray): Byte {
        val mostCommonByte = Basics.mostCommon(transposed_block)
        return mostCommonByte xor ' '.toByte()
    }

    fun findKey(keySize: Int): String {
        return String(transpose(keySize).map { tb -> findKeyLetter(tb) }.toByteArray())
    }
}
