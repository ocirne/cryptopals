package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics

class Challenge8 {

    private fun IntRange.pairs(): List<Pair<Int, Int>> {
        return this.flatMap { thisItem -> IntRange(thisItem + 1, this.last).map { thatItem -> thisItem to thatItem } }
    }

    private fun detectCollision(line: ByteArray): Boolean {
        val a = line.filterIndexed { index, _ -> index and 0xFF == 0 }
        val b = line.filterIndexed { index, _ -> index and 0xFF == 1 }
        return IntRange(0, 9).pairs().filter { (i, j) -> a[i] == a[j] && b[i] == b[j] }.any()
    }

    fun run(lines: List<String>): Int {
        return lines
            .map(Basics::decodeHexString)
            .indexOfFirst(this::detectCollision).inc()
    }
}
