package com.example.cryptography


import com.example.cryptography.Hash.convertToHex
import com.example.cryptography.Hash.hash256
import com.example.cryptography.Hash.hash3_256
import org.bouncycastle.jcajce.provider.digest.SHA3
import java.security.MessageDigest

object Hash {

    //1. convert inputString to byte array (output is 32 digits = 256/8 SHA256/UTF_8 - 8bit), i.e. hash is 256-bit = 32-byte)
    fun hash256(input: String): ByteArray {
        val digestSHA2 = MessageDigest.getInstance("SHA-256")
        val byteArray = digestSHA2.digest(input.toByteArray(Charsets.UTF_8))
        byteArray.forEach { i -> print("$i ") }
        println(" ")
        return byteArray
    }

    //2. convert byte array to String in hex
    fun convertToHex(byteArray: ByteArray): String {

        val hexString = StringBuffer()
        for (i in byteArray.indices) {
            val hex = Integer.toHexString(0xff and byteArray[i].toInt())
            if (hex.length == 1) hexString.append('0')
            print("$hex")
            hexString.append(hex)
        }
        println("\n")
        return hexString.toString()
    }

    // from JDK 9 - SHA3-256 is built in algorythm - MessageDigest.getInstance("SHA3-256")
    // here as using JDK 8 - library Bouncy Castle
    fun hash3_256(input: String): ByteArray {

        val digestSHA3 = SHA3.Digest256()
        val byteArray = digestSHA3.digest(input.toByteArray(Charsets.UTF_8))

        byteArray.forEach { i -> print("$i ") }
        println("\n")
        return byteArray
    }
}

fun main(args: Array<String>) {
    val inputString = "hello world"
    println("Final SHA-256: ${convertToHex(hash256(inputString))}")
    println("Final SHA3-256: ${convertToHex(hash3_256(inputString))}")


}

