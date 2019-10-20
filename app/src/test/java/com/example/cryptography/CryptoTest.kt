package com.example.cryptography

import org.junit.Assert.assertEquals
import org.junit.Test

class CryptoTest {

    val input: String = "hello world"

    @Test
    fun hash256Test() {
        val output = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assertEquals(Hash.convertToHex(Hash.hash256(input)), output)
    }

    @Test
    fun hash3_256Test() {
        val output = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"
        assertEquals(Hash.convertToHex(Hash.hash3_256(input)), output)
    }

    @Test
    fun base64Test() {
        val output = "aGVsbG8gd29ybGQ="
        assertEquals(Encode.base64Encode(input), output)
    }

    @Test
    fun urlEncodeTest() {
        val output = "https%3A%2F%2Fwww.google.co.nz%2F%3Fgfe_rd%3Dcr%26ei%3DdzbFV%26gws_rd%3Dssl%23q%3Djava"
        val inputUrl = "https://www.google.co.nz/?gfe_rd=cr&ei=dzbFV&gws_rd=ssl#q=java"
        assertEquals(Encode.urlEncode(inputUrl), output)
    }
}