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
        val digest: MessageDigest = MessageDigest.getInstance("SHA-256") //해시함수의 한 종류 - 32바이트의 해시값
        lateinit var token: ByteArray
    }

    // returns the ASN.1 OID of the given hash algorithm
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

    @Throws(Exception::class)
    private fun getTimeStampToken(
        messageImprint: ByteArray?
    ): ByteArray {
        digest.reset()
        val hash = digest.digest(messageImprint)

        // 32-bit cryptographic nonce
        val random = SecureRandom()
        val nonce = random.nextInt()

        // generate TSA request
        val tsaGenerator = TimeStampRequestGenerator()
        tsaGenerator.setCertReq(true)
        val oid = getHashObjectIdentifier(digest.algorithm)
        val request: TimeStampRequest = tsaGenerator.generate(oid, hash, BigInteger.valueOf(nonce.toLong()))

        // generate TimeStampToken
        val signerInfoGenerator: SignerInfoGenerator = JcaSimpleSignerInfoGeneratorBuilder().build("SHA256WithRSAEncryption", PdfSign.cert.privateKey, PdfSign.cert.certificate as X509Certificate)
        val digestCalculator: DigestCalculator = JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider()).build().get(signerInfoGenerator.digestAlgorithm)
        val tstGen = TimeStampTokenGenerator(
            signerInfoGenerator, digestCalculator, ASN1ObjectIdentifier("2.5.29.32.0")
        )
        val certList: MutableList<X509Certificate?> = ArrayList()
        certList.add(PdfSign.cert.certificate as X509Certificate)
        val certs = JcaCertStore(certList)
        tstGen.addCRLs(certs)
        tstGen.addCertificates(certs)

        return tstGen.generate(request, BigInteger.ONE, PdfSign.date).encoded
    }

    fun signTimeStamps(signedData: CMSSignedData): CMSSignedData {
        val signerStore = signedData.signerInfos
        val newSigners: MutableList<SignerInformation> = ArrayList()
        for (signer in signerStore.signers) newSigners.add(signTimeStamp(signer))
        return CMSSignedData.replaceSigners(signedData, SignerInformationStore(newSigners))
    }

    private fun signTimeStamp(signer: SignerInformation): SignerInformation {
        val unsignedAttributes = signer.unsignedAttributes
        var vector = ASN1EncodableVector()
        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector()
        }
        token = getTimeStampToken(signer.signature)

        val oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
        val signatureTimeStamp: ASN1Encodable = Attribute(oid, DERSet(ASN1Primitive.fromByteArray(token)))
        vector.add(signatureTimeStamp)
        val signedAttributes = Attributes(vector)
        return SignerInformation.replaceUnsignedAttributes(signer, AttributeTable(signedAttributes)) ?: return signer
    }
}