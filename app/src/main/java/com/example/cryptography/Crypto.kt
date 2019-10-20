package com.example.cryptography

import com.example.cryptography.CryptoAES.decryptAES
import com.example.cryptography.CryptoAES.encryptAES
import com.example.cryptography.CryptoAES.generateAESKey
import com.example.cryptography.CryptoRSA.decryptRSA
import com.example.cryptography.CryptoRSA.encryptRSA
import com.example.cryptography.CryptoRSA.generateRSAKeys
import java.security.KeyPair
import java.security.KeyPairGenerator
import javax.crypto.Cipher
import java.security.MessageDigest
import java.util.*
import javax.crypto.spec.SecretKeySpec


object CryptoRSA {

    // 1. generate KyePair
    fun generateRSAKeys(): KeyPair {

        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(2048)

        return keyGen.genKeyPair()
    }

    // 2. encrypt with private key
    fun encryptRSA(input: String, keyPair: KeyPair): ByteArray {
        val privateKey = keyPair.private
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, privateKey)

        return cipher.doFinal(input.toByteArray())
    }

    // 3. decrypt with public key
    fun decryptRSA(input: ByteArray, keyPair: KeyPair): String {
        val publicKey = keyPair.public
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, publicKey)

        return String(cipher.doFinal(input))
    }
}

object CryptoAES {

    // 1. generate key
    fun generateAESKey(myKey: String): SecretKeySpec {
        var sha: MessageDigest? = null

            var key = myKey.toByteArray(charset("UTF-8"))
            sha = MessageDigest.getInstance("SHA-1")
            key = sha.digest(key)
            key = Arrays.copyOf(key, 16)
            return SecretKeySpec(key, "AES")
    }

    fun encryptAES(input: String, key: SecretKeySpec): String {

        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return Base64.getEncoder().encodeToString(cipher.doFinal(input.toByteArray(charset("UTF-8"))))
    }

    fun decryptAES(input: String, key: SecretKeySpec): String {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING")
        cipher.init(Cipher.DECRYPT_MODE, key)
        return String(cipher.doFinal(Base64.getDecoder().decode(input)))
    }

}

fun main(args: Array<String>) {
    // RSA
    val input = "hello world"

    val keyPair = generateRSAKeys()
    val encryptedRSA = encryptRSA(input, keyPair)
    print("Encrypted RSA: ")
    encryptedRSA.forEach { i -> print("$i ") }
    println(" ")
    val decryptedRSA = decryptRSA(encryptedRSA, keyPair)
    println("Decrypted RSA: $decryptedRSA")

    // AES
    val key = generateAESKey("My secret key")
    val encryptedAES = encryptAES(input, key)
    println("Encrypted AES: $encryptedAES")
    val decryptedAES = decryptAES(encryptedAES, key)
    println("Decrypted AES: $decryptedAES")
}