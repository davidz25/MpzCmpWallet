package org.multipaz.samples.wallet.cmp

import kotlinx.datetime.Clock
import kotlinx.io.bytestring.encodeToByteString
import org.multipaz.asn1.ASN1Integer
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.trustmanagement.TrustPoint
import kotlin.time.Duration.Companion.days

suspend fun createSampleDocument(documentStore: DocumentStore, secureArea: SecureArea) {
    if (documentStore.listDocuments().isNotEmpty()) {
        return
    }

    val now = Clock.System.now()
    val signedAt = now
    val validFrom = now
    val validUntil = now + 365.days
    val iacaKey = Crypto.createEcPrivateKey(EcCurve.P256)
    val iacaCert = MdocUtil.generateIacaCertificate(
        iacaKey = iacaKey,
        subject = X500Name.fromName(name = "CN=Test IACA Key"),
        serial = ASN1Integer.fromRandom(numBits = 128),
        validFrom = validFrom,
        validUntil = validUntil,
        issuerAltNameUrl = "https://issuer.example.com",
        crlUrl = "https://issuer.example.com/crl"
    )
    val dsKey = Crypto.createEcPrivateKey(EcCurve.P256)
    val dsCert = MdocUtil.generateDsCertificate(
        iacaCert = iacaCert,
        iacaKey = iacaKey,
        dsKey = dsKey.publicKey,
        subject = X500Name.fromName(name = "CN=Test DS Key"),
        serial = ASN1Integer.fromRandom(numBits = 128),
        validFrom = validFrom,
        validUntil = validUntil
    )
    val document = documentStore.createDocument(
        displayName = "Erika's Driving License",
        typeDisplayName = "Utopia Driving License",
    )

    DrivingLicense.getDocumentType().createMdocCredentialWithSampleData(
        document = document,
        secureArea = secureArea,
        createKeySettings = CreateKeySettings(
            algorithm = Algorithm.ESP256,
            nonce = "Challenge".encodeToByteString(),
            userAuthenticationRequired = true
        ),
        dsKey = dsKey,
        dsCertChain = X509CertChain(listOf(dsCert)),
        signedAt = signedAt,
        validFrom = validFrom,
        validUntil = validUntil,
    )
}

fun createTestTrustManager(): TrustManager {
    return TrustManager().apply {
        val readerRootCert = X509Cert.fromPem(
            """
                -----BEGIN CERTIFICATE-----
                MIICUTCCAdegAwIBAgIQppKZHI1iPN290JKEA79OpzAKBggqhkjOPQQDAzArMSkwJwYDVQQDDCBP
                V0YgTXVsdGlwYXogVGVzdEFwcCBSZWFkZXIgUm9vdDAeFw0yNDEyMDEwMDAwMDBaFw0zNDEyMDEw
                MDAwMDBaMCsxKTAnBgNVBAMMIE9XRiBNdWx0aXBheiBUZXN0QXBwIFJlYWRlciBSb290MHYwEAYH
                KoZIzj0CAQYFK4EEACIDYgAE+QDye70m2O0llPXMjVjxVZz3m5k6agT+wih+L79b7jyqUl99sbeU
                npxaLD+cmB3HK3twkA7fmVJSobBc+9CDhkh3mx6n+YoH5RulaSWThWBfMyRjsfVODkosHLCDnbPV
                o4G/MIG8MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMFYGA1UdHwRPME0wS6BJ
                oEeGRWh0dHBzOi8vZ2l0aHViLmNvbS9vcGVud2FsbGV0LWZvdW5kYXRpb24tbGFicy9pZGVudGl0
                eS1jcmVkZW50aWFsL2NybDAdBgNVHQ4EFgQUq2Ub4FbCkFPx3X9s5Ie+aN5gyfUwHwYDVR0jBBgw
                FoAUq2Ub4FbCkFPx3X9s5Ie+aN5gyfUwCgYIKoZIzj0EAwMDaAAwZQIxANN9WUvI1xtZQmAKS4/D
                ZVwofqLNRZL/co94Owi1XH5LgyiBpS3E8xSxE9SDNlVVhgIwKtXNBEBHNA7FKeAxKAzu4+MUf4gz
                8jvyFaE0EUVlS2F5tARYQkU6udFePucVdloi
                -----END CERTIFICATE-----
            """.trimIndent().trim()
        )
        addTrustPoint(
            TrustPoint(
                certificate = readerRootCert,
                displayName = "OWF Multipaz TestApp",
                displayIcon = null
            )
        )
    }
} 