import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.Attributes
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInfoGenerator
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.SignerInformationStore
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.DigestCalculator
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.tsp.TimeStampRequest
import org.bouncycastle.tsp.TimeStampRequestGenerator
import org.bouncycastle.tsp.TimeStampTokenGenerator
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.ArrayList

class Tsa {
    companion object {
        // 해시 함수로 SHA-256을 사용하는 MessageDigest 객체
        val digest: MessageDigest = MessageDigest.getInstance("SHA-256")

        // Timestamp Token을 저장할 ByteArray 변수
        lateinit var token: ByteArray
    }

    // 주어진 해시 알고리즘에 대한 ASN.1 OID를 반환하는 함수
    private fun getHashObjectIdentifier(algorithm: String): ASN1ObjectIdentifier {
        return when (algorithm) {
            "MD2" -> ASN1ObjectIdentifier(PKCSObjectIdentifiers.md2.id)
            "MD5" -> ASN1ObjectIdentifier(PKCSObjectIdentifiers.md5.id)
            "SHA-1" -> ASN1ObjectIdentifier(OIWObjectIdentifiers.idSHA1.id)
            "SHA-224" -> ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha224.id)
            "SHA-256" -> ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha256.id)
            "SHA-384" -> ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha384.id)
            "SHA-512" -> ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha512.id)
            else -> ASN1ObjectIdentifier(algorithm)
        }
    }

    // Timestamp Token을 생성하여 반환하는 함수
    @Throws(Exception::class)
    private fun getTimeStampToken(messageImprint: ByteArray?): ByteArray {
        // MessageDigest 초기화 및 해시 계산
        digest.reset()
        val hash = digest.digest(messageImprint)

        // 32-bit cryptographic nonce 생성
        val random = SecureRandom()
        val nonce = random.nextInt()

        // TSA(Timestamp Authority) 요청 생성
        val tsaGenerator = TimeStampRequestGenerator()
        tsaGenerator.setCertReq(true)
        val oid = getHashObjectIdentifier(digest.algorithm)
        val request: TimeStampRequest = tsaGenerator.generate(oid, hash, BigInteger.valueOf(nonce.toLong()))

        // Timestamp Token 생성
        val signerInfoGenerator: SignerInfoGenerator = JcaSimpleSignerInfoGeneratorBuilder().build(
            "SHA256WithRSAEncryption",
            PdfSign.cert.privateKey,
            PdfSign.cert.certificate as X509Certificate
        )
        val digestCalculator: DigestCalculator = JcaDigestCalculatorProviderBuilder()
            .setProvider(BouncyCastleProvider())
            .build()
            .get(signerInfoGenerator.digestAlgorithm)
        val tstGen = TimeStampTokenGenerator(
            signerInfoGenerator, digestCalculator, ASN1ObjectIdentifier("2.5.29.32.0")
        )
        val certList: MutableList<X509Certificate?> = ArrayList()
        certList.add(PdfSign.cert.certificate as X509Certificate)
        val certs = JcaCertStore(certList)
        tstGen.addCRLs(certs)
        tstGen.addCertificates(certs)

        // Timestamp Token을 반환
        return tstGen.generate(request, BigInteger.ONE, PdfSign.date).encoded
    }

    // SignerInformation에 Timestamp Token을 추가하고 반환하는 함수
    private fun signTimeStamp(signer: SignerInformation): SignerInformation {
        // UnsignedAttributes 가져오기
        val unsignedAttributes = signer.unsignedAttributes
        var vector = ASN1EncodableVector()

        // UnsignedAttributes가 존재하면 vector에 추가
        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector()
        }

        // Timestamp Token 생성 및 추가
        token = getTimeStampToken(signer.signature)
        val oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
        val signatureTimeStamp: ASN1Encodable = Attribute(oid, DERSet(ASN1Primitive.fromByteArray(token)))
        vector.add(signatureTimeStamp)

        // 새로운 SignedAttributes 생성
        val signedAttributes = Attributes(vector)

        // UnsignedAttributes를 새로운 SignedAttributes로 교체하여 반환
        return SignerInformation.replaceUnsignedAttributes(signer, AttributeTable(signedAttributes)) ?: signer
    }

    // CMSSignedData에 있는 모든 SignerInformation에 대해 Timestamp Token을 추가하여 반환하는 함수
    fun signTimeStamps(signedData: CMSSignedData): CMSSignedData {
        val signerStore = signedData.signerInfos
        val newSigners: MutableList<SignerInformation> = mutableListOf()

        // 모든 SignerInformation에 대해 Timestamp Token 추가
        for (signer in signerStore.signers) {
            newSigners.add(signTimeStamp(signer))
        }

        // 기존의 SignerInformation을 새로운 것으로 교체하여 반환
        return CMSSignedData.replaceSigners(signedData, SignerInformationStore(newSigners))
    }
}
