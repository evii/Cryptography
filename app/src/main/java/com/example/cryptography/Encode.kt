package com.example.cryptography


import com.example.cryptography.Encode.base64Encode
import com.example.cryptography.Encode.urlEncode
import java.net.URLEncoder
import java.util.*
import java.util.Base64.getUrlEncoder



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

    fun urlEncode (input: String): String {
        return URLEncoder.encode(input, "UTF-8")
    }
 }

fun main(args: Array<String>) {
    println(base64Encode("hello world"))
    println(urlEncode("https://www.google.co.nz/?gfe_rd=cr&ei=dzbFV&gws_rd=ssl#q=java"))
}