package com.example.cryptography

import org.junit.Assert.assertEquals
import org.junit.Test

class CryptoTest {

    val input: String = "hello world"
    val outputX509Cert = "[\n" +
            "[\n" +
            "  Version: V3\n" +
            "  Subject: CN=*.facebook.com, O=\"Facebook, Inc.\", L=Menlo Park, ST=California, C=US\n" +
            "  Signature Algorithm: SHA256withRSA, OID = 1.2.840.113549.1.1.11\n" +
            "\n" +
            "  Key:  Sun EC public key, 256 bits\n" +
            "  public x coord: 69902877814810619024667934810771413532645834830140884192955182843395646690771\n" +
            "  public y coord: 26188856844139700910045906872242159688068094826581938247896523569790721146670\n" +
            "  parameters: secp256r1 [NIST P-256, X9.62 prime256v1] (1.2.840.10045.3.1.7)\n" +
            "  Validity: [From: Fri Dec 06 01:00:00 CET 2019,\n" +
            "               To: Thu Mar 05 13:00:00 CET 2020]\n" +
            "  Issuer: CN=DigiCert SHA2 High Assurance Server CA, OU=www.digicert.com, O=DigiCert Inc, C=US\n" +
            "  SerialNumber: [    079786f7 6b8e7bc8 71cc255a 5cb6fd08]\n" +
            "\n" +
            "Certificate Extensions: 10\n" +
            "[1]: ObjectId: 1.3.6.1.4.1.11129.2.4.2 Criticality=false\n" +
            "Extension unknown: DER encoded OCTET string =\n" +
            "0000: 04 81 F5 04 81 F2 00 F0   00 76 00 BB D9 DF BC 1F  .........v......\n" +
            "0010: 8A 71 B5 93 94 23 97 AA   92 7B 47 38 57 95 0A AB  .q...#....G8W...\n" +
            "0020: 52 E8 1A 90 96 64 36 8E   1E D1 85 00 00 01 6E DC  R....d6.......n.\n" +
            "0030: 2F A4 D7 00 00 04 03 00   47 30 45 02 20 3A BA 79  /.......G0E. :.y\n" +
            "0040: 45 8C 7D 0C D8 ED A3 0A   95 36 81 80 64 A0 65 96  E........6..d.e.\n" +
            "0050: 45 8D 23 1E 25 33 11 75   D7 9C 2B 2A 83 02 21 00  E.#.%3.u..+*..!.\n" +
            "0060: A1 B6 6A BF E3 25 D9 F9   84 A5 30 76 67 72 FD B5  ..j..%....0vgr..\n" +
            "0070: CC 20 A5 67 4E E8 46 7B   03 E0 F9 C2 5E FE 5D A1  . .gN.F.....^.].\n" +
            "0080: 00 76 00 5E A7 73 F9 DF   56 C0 E7 B5 36 48 7D D0  .v.^.s..V...6H..\n" +
            "0090: 49 E0 32 7A 91 9A 0C 84   A1 12 12 84 18 75 96 81  I.2z.........u..\n" +
            "00A0: 71 45 58 00 00 01 6E DC   2F A4 78 00 00 04 03 00  qEX...n./.x.....\n" +
            "00B0: 47 30 45 02 20 33 86 95   36 CE B3 06 FD BF 06 83  G0E. 3..6.......\n" +
            "00C0: FE FF 4F 57 CA A0 25 46   DC 72 EA D1 E1 A7 E0 C0  ..OW..%F.r......\n" +
            "00D0: 92 26 B5 D8 62 02 21 00   9C 06 6E 6C F8 E8 FE 3D  .&..b.!...nl...=\n" +
            "00E0: EF 0C 61 69 C1 13 1D F8   A9 41 18 C8 9F C8 B8 AD  ..ai.....A......\n" +
            "00F0: 77 D2 23 7D C7 05 CD A9                            w.#.....\n" +
            "\n" +
            "\n" +
            "[2]: ObjectId: 1.3.6.1.5.5.7.1.1 Criticality=false\n" +
            "AuthorityInfoAccess [\n" +
            "  [\n" +
            "   accessMethod: ocsp\n" +
            "   accessLocation: URIName: http://ocsp.digicert.com\n" +
            ", \n" +
            "   accessMethod: caIssuers\n" +
            "   accessLocation: URIName: http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt\n" +
            "]\n" +
            "]\n" +
            "\n" +
            "[3]: ObjectId: 2.5.29.35 Criticality=false\n" +
            "AuthorityKeyIdentifier [\n" +
            "KeyIdentifier [\n" +
            "0000: 51 68 FF 90 AF 02 07 75   3C CC D9 65 64 62 A2 12  Qh.....u<..edb..\n" +
            "0010: B8 59 72 3B                                        .Yr;\n" +
            "]\n" +
            "]\n" +
            "\n" +
            "[4]: ObjectId: 2.5.29.19 Criticality=true\n" +
            "BasicConstraints:[\n" +
            "  CA:false\n" +
            "  PathLen: undefined\n" +
            "]\n" +
            "\n" +
            "[5]: ObjectId: 2.5.29.31 Criticality=false\n" +
            "CRLDistributionPoints [\n" +
            "  [DistributionPoint:\n" +
            "     [URIName: http://crl3.digicert.com/sha2-ha-server-g6.crl]\n" +
            ", DistributionPoint:\n" +
            "     [URIName: http://crl4.digicert.com/sha2-ha-server-g6.crl]\n" +
            "]]\n" +
            "\n" +
            "[6]: ObjectId: 2.5.29.32 Criticality=false\n" +
            "CertificatePolicies [\n" +
            "  [CertificatePolicyId: [2.16.840.1.114412.1.1]\n" +
            "[PolicyQualifierInfo: [\n" +
            "  qualifierID: 1.3.6.1.5.5.7.2.1\n" +
            "  qualifier: 0000: 16 1C 68 74 74 70 73 3A   2F 2F 77 77 77 2E 64 69  ..https://www.di\n" +
            "0010: 67 69 63 65 72 74 2E 63   6F 6D 2F 43 50 53        gicert.com/CPS\n" +
            "\n" +
            "]]  ]\n" +
            "  [CertificatePolicyId: [2.23.140.1.2.2]\n" +
            "[]  ]\n" +
            "]\n" +
            "\n" +
            "[7]: ObjectId: 2.5.29.37 Criticality=false\n" +
            "ExtendedKeyUsages [\n" +
            "  serverAuth\n" +
            "  clientAuth\n" +
            "]\n" +
            "\n" +
            "[8]: ObjectId: 2.5.29.15 Criticality=true\n" +
            "KeyUsage [\n" +
            "  DigitalSignature\n" +
            "]\n" +
            "\n" +
            "[9]: ObjectId: 2.5.29.17 Criticality=false\n" +
            "SubjectAlternativeName [\n" +
            "  DNSName: *.facebook.com\n" +
            "  DNSName: *.facebook.net\n" +
            "  DNSName: *.fb.com\n" +
            "  DNSName: *.fbcdn.net\n" +
            "  DNSName: *.fbsbx.com\n" +
            "  DNSName: *.messenger.com\n" +
            "  DNSName: facebook.com\n" +
            "  DNSName: fb.com\n" +
            "  DNSName: messenger.com\n" +
            "  DNSName: *.m.facebook.com\n" +
            "  DNSName: *.xx.fbcdn.net\n" +
            "  DNSName: *.xy.fbcdn.net\n" +
            "  DNSName: *.xz.fbcdn.net\n" +
            "]\n" +
            "\n" +
            "[10]: ObjectId: 2.5.29.14 Criticality=false\n" +
            "SubjectKeyIdentifier [\n" +
            "KeyIdentifier [\n" +
            "0000: 8C 27 59 0A D6 7A ED AE   4E F1 72 D3 10 07 15 A4  .'Y..z..N.r.....\n" +
            "0010: 2F 94 67 3C                                        /.g<\n" +
            "]\n" +
            "]\n" +
            "\n" +
            "]\n" +
            "  Algorithm: [SHA256withRSA]\n" +
            "  Signature:\n" +
            "0000: A3 0E 22 DC 16 90 66 D3   C5 FA 30 E7 73 BC 2F 67  ..\"...f...0.s./g\n" +
            "0010: 15 73 38 36 AC 5E 3F BA   96 50 30 67 AC CE 2C FB  .s86.^?..P0g..,.\n" +
            "0020: 4A 96 63 66 AF 33 01 E4   56 C4 46 A4 53 A0 79 AA  J.cf.3..V.F.S.y.\n" +
            "0030: 12 A4 5A 81 F4 FB 28 B2   DA E9 7D A9 16 C2 6B 01  ..Z...(.......k.\n" +
            "0040: B0 E1 89 B9 29 90 41 F4   B1 F2 2E 75 84 8E A1 3B  ....).A....u...;\n" +
            "0050: F4 2A 71 15 D1 62 BB 67   5F 87 3F A5 8F 87 EC F4  .*q..b.g_.?.....\n" +
            "0060: 22 43 63 6E 16 A1 76 54   4A CD E7 EB 7C 53 DF 3D  \"Ccn..vTJ....S.=\n" +
            "0070: 2A 34 91 32 B0 38 0C C6   47 A9 10 A7 20 2D 27 8B  *4.2.8..G... -'.\n" +
            "0080: 86 39 08 D2 B6 3D D5 43   09 94 1F 6F 01 3B B5 20  .9...=.C...o.;. \n" +
            "0090: A1 E0 00 9A 28 1D E8 82   37 30 96 92 31 10 B7 3B  ....(...70..1..;\n" +
            "00A0: C4 75 B8 E8 AA CB F8 03   0C 57 FE 45 66 68 52 32  .u.......W.EfhR2\n" +
            "00B0: 52 BA 42 D2 62 F6 30 E4   97 81 84 B3 5B 30 C8 8A  R.B.b.0.....[0..\n" +
            "00C0: 5E 7A F6 4B 45 97 C0 98   2C 2C B4 33 54 3B 70 0E  ^z.KE...,,.3T;p.\n" +
            "00D0: 70 DC FB 24 0C EF 7F 6F   D9 87 4F E8 4E F5 66 30  p..\$...o..O.N.f0\n" +
            "00E0: 81 E8 7C B7 7A 03 C2 BD   EB 51 AE B0 D0 4E 36 44  ....z....Q...N6D\n" +
            "00F0: 21 0F 59 82 B3 CB 89 A6   EA 46 93 85 F2 84 C5 4D  !.Y......F.....M\n" +
            "\n" +
            "]"

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

    @Test
    fun RSACryptografyTest() {
        val keyPair = CryptoRSA.generateRSAKeys()
        val encrypted = CryptoRSA.encryptRSA(input, keyPair)
        val decrypted = CryptoRSA.decryptRSA(encrypted, keyPair)
        assertEquals(decrypted, input)
    }

    @Test
    fun AESCryptografyTest() {
        val secretKey = "My secret key"
        val key = CryptoAES.generateAESKey(secretKey)
        val encrypted = CryptoAES.encryptAES(input, key)
        val decrypted = CryptoAES.decryptAES(encrypted, key)
        assertEquals(decrypted, input)
    }

    @Test
    fun ImportX509CertificateTest() {
        val input = "-----BEGIN CERTIFICATE-----\n" +
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

        assertEquals(Certificate.importX509Certificate(input).toString(), outputX509Cert)
    }

}