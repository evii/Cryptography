package com.example.cryptography

import org.junit.Assert.assertEquals
import org.junit.Test

class HashTest {

    val input: String = "hello world"

    @Test
    fun hash256Test() {
        val output = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assertEquals(HashFunctions.convertToHex(HashFunctions.hash256(input)), output)
    }

    @Test
    fun hash3_256Test() {
        val output = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"
        assertEquals(HashFunctions.convertToHex(HashFunctions.hash3_256(input)), output)
    }
}