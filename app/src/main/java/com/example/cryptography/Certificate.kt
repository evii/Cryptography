package com.example.cryptography

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

object Certificate {

    fun importX509Certificate(certificate: String): X509Certificate {
        // get certificateFactory
        val certificateFactory = CertificateFactory.getInstance("X.509")
        // get byteArray from crt (Base64)
        val certificateByteArray = Base64.getDecoder().decode(certificate)
        // generate X509 certificate
        val inputStream = ByteArrayInputStream(certificateByteArray)
        return certificateFactory.generateCertificate(inputStream) as X509Certificate
    }
}

fun main() {
    val input = ""
    val output = Certificate.importX509Certificate(input)
    println(output)
}