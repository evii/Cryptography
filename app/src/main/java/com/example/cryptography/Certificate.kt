package com.example.cryptography

import com.example.cryptography.Certificate.facebookCertificate
import com.example.cryptography.Certificate.googleCertificate
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

object Certificate {

    val header = "-----BEGIN CERTIFICATE-----"
    val footer = "-----END CERTIFICATE-----"

    val googleCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIJRTCCCC2gAwIBAgIQId276PtDYAkIAAAAAB2KRjANBgkqhkiG9w0BAQsFADBC\n" +
            "MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMw\n" +
            "EQYDVQQDEwpHVFMgQ0EgMU8xMB4XDTE5MTEwNTA3NDYxNloXDTIwMDEyODA3NDYx\n" +
            "NlowZjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT\n" +
            "DU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxFTATBgNVBAMMDCou\n" +
            "Z29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABETwWPdIiJP2EXiE\n" +
            "+YH4oKgNNT/vgfFFf6Ssm7+UgJf0qZ+oY63xqfhEbOLu0J0agXa5oLGYkMedgHhw\n" +
            "Ags/F26jggbcMIIG2DAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUH\n" +
            "AwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU2VYFohFero6gqXjGUx+pPh8vq3Aw\n" +
            "HwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswZAYIKwYBBQUHAQEEWDBW\n" +
            "MCcGCCsGAQUFBzABhhtodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxbzEwKwYIKwYB\n" +
            "BQUHMAKGH2h0dHA6Ly9wa2kuZ29vZy9nc3IyL0dUUzFPMS5jcnQwggSdBgNVHREE\n" +
            "ggSUMIIEkIIMKi5nb29nbGUuY29tgg0qLmFuZHJvaWQuY29tghYqLmFwcGVuZ2lu\n" +
            "ZS5nb29nbGUuY29tghIqLmNsb3VkLmdvb2dsZS5jb22CGCouY3Jvd2Rzb3VyY2Uu\n" +
            "Z29vZ2xlLmNvbYIGKi5nLmNvgg4qLmdjcC5ndnQyLmNvbYIRKi5nY3BjZG4uZ3Z0\n" +
            "MS5jb22CCiouZ2dwaHQuY26CDiouZ2tlY25hcHBzLmNughYqLmdvb2dsZS1hbmFs\n" +
            "eXRpY3MuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUuY2yCDiouZ29vZ2xlLmNv\n" +
            "Lmlugg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28udWuCDyouZ29vZ2xlLmNv\n" +
            "bS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5jb20uYnKCDyouZ29vZ2xl\n" +
            "LmNvbS5jb4IPKi5nb29nbGUuY29tLm14gg8qLmdvb2dsZS5jb20udHKCDyouZ29v\n" +
            "Z2xlLmNvbS52boILKi5nb29nbGUuZGWCCyouZ29vZ2xlLmVzggsqLmdvb2dsZS5m\n" +
            "coILKi5nb29nbGUuaHWCCyouZ29vZ2xlLml0ggsqLmdvb2dsZS5ubIILKi5nb29n\n" +
            "bGUucGyCCyouZ29vZ2xlLnB0ghIqLmdvb2dsZWFkYXBpcy5jb22CDyouZ29vZ2xl\n" +
            "YXBpcy5jboIRKi5nb29nbGVjbmFwcHMuY26CFCouZ29vZ2xlY29tbWVyY2UuY29t\n" +
            "ghEqLmdvb2dsZXZpZGVvLmNvbYIMKi5nc3RhdGljLmNugg0qLmdzdGF0aWMuY29t\n" +
            "ghIqLmdzdGF0aWNjbmFwcHMuY26CCiouZ3Z0MS5jb22CCiouZ3Z0Mi5jb22CFCou\n" +
            "bWV0cmljLmdzdGF0aWMuY29tggwqLnVyY2hpbi5jb22CECoudXJsLmdvb2dsZS5j\n" +
            "b22CEyoud2Vhci5na2VjbmFwcHMuY26CFioueW91dHViZS1ub2Nvb2tpZS5jb22C\n" +
            "DSoueW91dHViZS5jb22CFioueW91dHViZWVkdWNhdGlvbi5jb22CESoueW91dHVi\n" +
            "ZWtpZHMuY29tggcqLnl0LmJlggsqLnl0aW1nLmNvbYIaYW5kcm9pZC5jbGllbnRz\n" +
            "Lmdvb2dsZS5jb22CC2FuZHJvaWQuY29tghtkZXZlbG9wZXIuYW5kcm9pZC5nb29n\n" +
            "bGUuY26CHGRldmVsb3BlcnMuYW5kcm9pZC5nb29nbGUuY26CBGcuY2+CCGdncGh0\n" +
            "LmNuggxna2VjbmFwcHMuY26CBmdvby5nbIIUZ29vZ2xlLWFuYWx5dGljcy5jb22C\n" +
            "Cmdvb2dsZS5jb22CD2dvb2dsZWNuYXBwcy5jboISZ29vZ2xlY29tbWVyY2UuY29t\n" +
            "ghhzb3VyY2UuYW5kcm9pZC5nb29nbGUuY26CCnVyY2hpbi5jb22CCnd3dy5nb28u\n" +
            "Z2yCCHlvdXR1LmJlggt5b3V0dWJlLmNvbYIUeW91dHViZWVkdWNhdGlvbi5jb22C\n" +
            "D3lvdXR1YmVraWRzLmNvbYIFeXQuYmUwIQYDVR0gBBowGDAIBgZngQwBAgIwDAYK\n" +
            "KwYBBAHWeQIFAzAvBgNVHR8EKDAmMCSgIqAghh5odHRwOi8vY3JsLnBraS5nb29n\n" +
            "L0dUUzFPMS5jcmwwggEGBgorBgEEAdZ5AgQCBIH3BIH0APIAdwCyHgXMi6LNiiBO\n" +
            "h2b5K7mKJSBna9r6cOeySVMt74uQXgAAAW46vlHbAAAEAwBIMEYCIQDpOV89u5Eq\n" +
            "OAN3utS9vvXK6b9qwnYgsiRvTDPzKj/RMgIhAJtf5vPM60HYJDIMIDreUJ9FJXN1\n" +
            "gZ80iPCWa3XJfMv9AHcAXqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVgA\n" +
            "AAFuOr5SDgAABAMASDBGAiEAluuJTunQX+sOvRtgoGi5FWjLmSyfkR9FoxlTIwI9\n" +
            "MPACIQDrvOpik5EGkKCHQYQzjHjEJs/6oMN8snfsFkaspC1pZzANBgkqhkiG9w0B\n" +
            "AQsFAAOCAQEAS2pcPhrdskAIb3lACvzVmnxGb/dGBHZ9tIYe3a7UEmcVnl1mlNzW\n" +
            "WLakbhXymqJO9XZdD++LVbrS/TTFXkTC8s+D+3xLsA31KcKaCRcs/k3iibnxo6DQ\n" +
            "MXvo52aadZh4NiocEabMUgzjZy5XPN6+YuC/5UtvRmC2hEOfxNkZK7WhhfJq+MoT\n" +
            "uIV5g221GpWCprnFmMb9JCjZg3jR88kAoITUR7rJnKXQLOu7HInluBrcgg9m5/Au\n" +
            "m9yfBV3TyeD/LWwi36qL9jh2h8L9+p0jLpQcYOD15YC+jtxzvBizqOnlri6cZB34\n" +
            "sHSsW8ZSGFpLvazW8Amlsgtt121wNo1ehQ==\n" +
            "-----END CERTIFICATE-----"

    val facebookCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGODCCBSCgAwIBAgIQB5eG92uOe8hxzCVaXLb9CDANBgkqhkiG9w0BAQsFADBw\n" +
            "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n" +
            "d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNz\n" +
            "dXJhbmNlIFNlcnZlciBDQTAeFw0xOTEyMDYwMDAwMDBaFw0yMDAzMDUxMjAwMDBa\n" +
            "MGkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRMwEQYDVQQHEwpN\n" +
            "ZW5sbyBQYXJrMRcwFQYDVQQKEw5GYWNlYm9vaywgSW5jLjEXMBUGA1UEAwwOKi5m\n" +
            "YWNlYm9vay5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASai6BzahqaQkEj\n" +
            "cILiPj1OWAZ7GzgChQP5A27wPRgV0znmXiDbiKBbjeee08w7kl239CLhOvMWNYzF\n" +
            "x0/7bz8uo4IDnjCCA5owHwYDVR0jBBgwFoAUUWj/kK8CB3U8zNllZGKiErhZcjsw\n" +
            "HQYDVR0OBBYEFIwnWQrWeu2uTvFy0xAHFaQvlGc8MIHHBgNVHREEgb8wgbyCDiou\n" +
            "ZmFjZWJvb2suY29tgg4qLmZhY2Vib29rLm5ldIIIKi5mYi5jb22CCyouZmJjZG4u\n" +
            "bmV0ggsqLmZic2J4LmNvbYIPKi5tZXNzZW5nZXIuY29tggxmYWNlYm9vay5jb22C\n" +
            "BmZiLmNvbYINbWVzc2VuZ2VyLmNvbYIQKi5tLmZhY2Vib29rLmNvbYIOKi54eC5m\n" +
            "YmNkbi5uZXSCDioueHkuZmJjZG4ubmV0gg4qLnh6LmZiY2RuLm5ldDAOBgNVHQ8B\n" +
            "Af8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHUGA1UdHwRu\n" +
            "MGwwNKAyoDCGLmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWhhLXNlcnZl\n" +
            "ci1nNi5jcmwwNKAyoDCGLmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWhh\n" +
            "LXNlcnZlci1nNi5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAQEwKjAoBggrBgEF\n" +
            "BQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBAgIwgYMG\n" +
            "CCsGAQUFBwEBBHcwdTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu\n" +
            "Y29tME0GCCsGAQUFBzAChkFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln\n" +
            "aUNlcnRTSEEySGlnaEFzc3VyYW5jZVNlcnZlckNBLmNydDAMBgNVHRMBAf8EAjAA\n" +
            "MIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYAu9nfvB+KcbWTlCOXqpJ7RzhXlQqr\n" +
            "UugakJZkNo4e0YUAAAFu3C+k1wAABAMARzBFAiA6unlFjH0M2O2jCpU2gYBkoGWW\n" +
            "RY0jHiUzEXXXnCsqgwIhAKG2ar/jJdn5hKUwdmdy/bXMIKVnTuhGewPg+cJe/l2h\n" +
            "AHYAXqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVgAAAFu3C+keAAABAMA\n" +
            "RzBFAiAzhpU2zrMG/b8Gg/7/T1fKoCVG3HLq0eGn4MCSJrXYYgIhAJwGbmz46P49\n" +
            "7wxhacETHfipQRjIn8i4rXfSI33HBc2pMA0GCSqGSIb3DQEBCwUAA4IBAQCjDiLc\n" +
            "FpBm08X6MOdzvC9nFXM4NqxeP7qWUDBnrM4s+0qWY2avMwHkVsRGpFOgeaoSpFqB\n" +
            "9PsostrpfakWwmsBsOGJuSmQQfSx8i51hI6hO/QqcRXRYrtnX4c/pY+H7PQiQ2Nu\n" +
            "FqF2VErN5+t8U989KjSRMrA4DMZHqRCnIC0ni4Y5CNK2PdVDCZQfbwE7tSCh4ACa\n" +
            "KB3ogjcwlpIxELc7xHW46KrL+AMMV/5FZmhSMlK6QtJi9jDkl4GEs1swyIpeevZL\n" +
            "RZfAmCwstDNUO3AOcNz7JAzvf2/Zh0/oTvVmMIHofLd6A8K961GusNBONkQhD1mC\n" +
            "s8uJpupGk4XyhMVN\n" +
            "-----END CERTIFICATE-----"

    fun importX509Certificate(certificate: String): X509Certificate {

        // remove header and footer
        val cleanCertificate = certificate.substring(header.length, certificate.length - footer.length)

        // get certificateFactory
        val certificateFactory = CertificateFactory.getInstance("X.509")

        // get byteArray from certificate String (Base64) - MimeDecoder enables to decode delimited string
        val certificateByteArray = Base64.getMimeDecoder().decode(cleanCertificate)

        // generate X509 certificate
        val inputStream = ByteArrayInputStream(certificateByteArray)
        return certificateFactory.generateCertificate(inputStream) as X509Certificate
    }
}

fun main() {
    val googleX509 = Certificate.importX509Certificate(googleCertificate)
    println("Google cert: " + googleX509)

    val facebookX509 = Certificate.importX509Certificate(facebookCertificate)
    println("Facebook cert: " + facebookX509)
}