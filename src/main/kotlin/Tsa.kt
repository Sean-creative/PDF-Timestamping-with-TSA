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

class Tsa {
    companion object {
        // 해시 함수로 SHA-256을 사용하는 MessageDigest 객체
        val digest: MessageDigest = MessageDigest.getInstance("SHA-256")

        // Timestamp Token을 저장할 ByteArray 변수
        lateinit var timeStampToken: ByteArray
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
    private fun getTimeStampToken(signature: ByteArray?): ByteArray {
        //만약 이전에 다른 데이터에 대한 해시를 계산했다면, 그 상태를 초기화하여 새로운 데이터에 대한 해시를 계산할 수 있도록함
        digest.reset()
        //signature 바이트 배열에 대한 해시 값을 계산
        val hash = digest.digest(signature)

        // 암호학적으로 안전한 난수를 생성
        val random = SecureRandom()
        // 32-bit 난수 생성
        val nonce = random.nextInt()
        // nonce 변수에 저장된 값은 나중에 Timestamp Token을 생성할 때 서버에 의해 생성된 고유한 값으로 사용될 수 있습니다.
        // 이러한 고유한 값은 Replay 공격과 같은 보안 문제를 방지하는 데 사용됩니다.
        // Replay 공격은 이전에 생성된 타임스탬프를 다시 사용하여 시간을 조작하려는 시도를 가리킵니다.


        // TimeStampRequestGenerator = Timestamp Token을 요청하기 위한 정보를 생성하는 데 사용
        val timeStampRequestGenerator = TimeStampRequestGenerator()
        // 인증서를 요청하도록 설정
        timeStampRequestGenerator.setCertReq(true)

        // 현재 해시 알고리즘에 해당하는 ASN.1 OID (Object Identifier)를 가져옴
        val oid = getHashObjectIdentifier(digest.algorithm)
        // timeStampRequestGenerator에게 전송할 Timestamp Token 요청을 생성합니다.
        // oid는 사용된 해시 알고리즘의 OID이고, hash는 서명에 사용된 데이터의 해시 값입니다.
        // BigInteger.valueOf(nonce.toLong())는 Replay 공격을 방지하기 위해 생성된 고유한 난수입니다.
        val request: TimeStampRequest = timeStampRequestGenerator.generate(oid, hash, BigInteger.valueOf(nonce.toLong()))

        // 서명 정보를 생성
        val signerInfoGenerator: SignerInfoGenerator = JcaSimpleSignerInfoGeneratorBuilder().build(
            "SHA256WithRSAEncryption",
            PdfSign.cert.privateKey,
            PdfSign.cert.certificate as X509Certificate
        )
        // DigestCalculator는 해시를 계산하는데 사용
        val digestCalculator: DigestCalculator = JcaDigestCalculatorProviderBuilder()
            .setProvider(BouncyCastleProvider())
            .build()
            .get(signerInfoGenerator.digestAlgorithm)

        // TimeStampTokenGenerator를 통해 나중에 타임스탬프 토큰을 생성
        val timeStampTokenGenerator = TimeStampTokenGenerator(
            signerInfoGenerator, digestCalculator, ASN1ObjectIdentifier("2.5.29.32.0")
        )

        val certList: MutableList<X509Certificate?> = mutableListOf()
        certList.add(PdfSign.cert.certificate as X509Certificate)
        val certs = JcaCertStore(certList)
        //서명 시간 정보를 담은 타임스탬프 토큰에 추가적인 보안 관련 정보를 첨부
        timeStampTokenGenerator.addCRLs(certs)
        timeStampTokenGenerator.addCertificates(certs)

        // Timestamp Token을 반환
        return timeStampTokenGenerator.generate(request, BigInteger.ONE, PdfSign.date).encoded
    }


    // SignerInformation에 Timestamp Token을 추가하고 반환하는 함수
    private fun signTimeStamp(signer: SignerInformation): SignerInformation {
        // ASN1은 데이터 구조와 표현을 기술하기 위한 표준
        var vector = ASN1EncodableVector()

        // UnsignedAttributes가 존재하면 vector에 추가
        if (signer.unsignedAttributes != null) {
            vector = signer.unsignedAttributes.toASN1EncodableVector()
        }

        // 현재 signer에 대한 Timestamp Token을 얻음
        timeStampToken = getTimeStampToken(signer.signature)
        // Timestamp Token을 나타내는 ASN1 객체 식별자(OID)를 설정
        val oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
        // ASN1 구조를 이용하여 Timestamp Token을 포함하는 Attribute 객체를 생성
        // oid는 Timestamp Token을 식별하는데 사용되며, DERSet을 이용하여 token을 ASN.1으로 변환한 후 Attribute에 추가
        val signatureTimeStamp: ASN1Encodable = Attribute(oid, DERSet(ASN1Primitive.fromByteArray(timeStampToken)))
        // 앞에서 생성한 Attribute 객체를 vector에 추가
        // vector는 나중에 SignerInformation 객체에 추가될 UnsignedAttributes의 일부로 사용됩니다.
        vector.add(signatureTimeStamp)

        // 새로운 SignedAttributes 생성
        val signedAttributes = Attributes(vector)

        // 새로운 SignedAttributes를 만들 때 기존의 UnsignedAttributes를 포함하여 반환
        return SignerInformation.replaceUnsignedAttributes(signer, AttributeTable(signedAttributes)) ?: signer
    }


    // CMSSignedData에 있는 각 SignerInformation에 대해 Timestamp Token을 추가하여 새로운 CMSSignedData 객체를 반환하는 함수
    // 기존의 서명 데이터에 각 서명자의 Timestamp Token을 추가하여 새로운 서명 데이터를 생성하는 역할
    fun signTimeStamps(cmsSignedData: CMSSignedData): CMSSignedData {
        //각 서명자(SignerInformation)에 대한 정보를 담고 있는 SignerInformationStore를 가져옵니다.
        val signerStore = cmsSignedData.signerInfos
        val newSigners: MutableList<SignerInformation> = mutableListOf()

        // 모든 SignerInformation에 대해 Timestamp Token 추가
        for (signer in signerStore.signers) {
            newSigners.add(signTimeStamp(signer))
        }

        // 기존의 SignerInformation을 새로운 것으로 교체하여 반환
        return CMSSignedData.replaceSigners(cmsSignedData, SignerInformationStore(newSigners))
    }
}
