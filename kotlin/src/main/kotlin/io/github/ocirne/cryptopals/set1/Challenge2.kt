package io.github.ocirne.cryptopals.set1

import com.google.common.io.BaseEncoding
import kotlin.experimental.xor

class Challenge2 {

    fun fixedXor(t: String, s: String): Any {
        val tBa = BaseEncoding.base16().decode(t.toUpperCase())
        val sBa = BaseEncoding.base16().decode(s.toUpperCase())
        val cBa = tBa.zip(sBa).map { (a, b) -> a.xor(b) }.toByteArray()
        return BaseEncoding.base16().encode(cBa).toLowerCase()
    }
}
