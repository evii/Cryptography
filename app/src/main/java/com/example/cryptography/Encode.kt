package com.example.cryptography


import com.example.cryptography.Encode.base64Encode
import com.example.cryptography.Encode.base64decode
import com.example.cryptography.Encode.urlEncode
import java.net.URLEncoder
import java.util.*

object Encode {

    fun base64Encode(input: String): String {
        // 1. get binary data = byte array from input
        val byteArray = input.toByteArray(charset("UTF-8"))
        byteArray.forEach { i -> print("$i ") }
        println(" ")
        // 2. assign ASCII to each byte
        val output = Base64.getEncoder().encodeToString(byteArray)
        println(output)
        return output
    }

    fun base64decode(input: String): String {
        val decodedString = Base64.getDecoder().decode(input.toByteArray(charset("UTF-8")))
        val actualString = String(decodedString)
        return actualString
    }

    fun urlEncode (input: String): String {
        return URLEncoder.encode(input, "UTF-8")
    }
 }

fun main(args: Array<String>) {
    println("Encoded: " + base64Encode("hello world"))
    println("Decoded: " + (base64decode(base64Encode("hello world"))).toString())
    println("Encoded url: " + urlEncode("https://www.google.co.nz/?gfe_rd=cr&ei=dzbFV&gws_rd=ssl#q=java"))
}