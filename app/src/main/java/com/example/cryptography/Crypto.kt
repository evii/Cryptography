package com.example.cryptography

import com.example.cryptography.Crypto.decryptRSA
import com.example.cryptography.Crypto.encryptRSA
import com.example.cryptography.Crypto.generateRSAKeys
import java.security.KeyPair
import java.security.KeyPairGenerator
import javax.crypto.Cipher

object Crypto {

    // 1. generating KyePair
    fun generateRSAKeys(): KeyPair {

        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(2048)

        return keyGen.genKeyPair()
    }

    // 2. encrypting with private key
    fun encryptRSA(input: String, keyPair: KeyPair): ByteArray {
        val privateKey = keyPair.private
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, privateKey)

        return cipher.doFinal(input.toByteArray())
    }

    // 3. decrypting with public key
    fun decryptRSA(input: ByteArray, keyPair: KeyPair): String {
        val publicKey = keyPair.public
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, publicKey)

        return String(cipher.doFinal(input))
    }
}

fun main(args: Array<String>) {
    val input = "hello world"
    val keyPair = generateRSAKeys()
    val encrypted = encryptRSA(input, keyPair)
    print("Encrypted: ")
    encrypted.forEach { i -> print("$i ") }
    println(" ")
    val decrypted = decryptRSA(encrypted, keyPair)
    println("Decrypted: $decrypted")
}