package util

import PdfSign
import Tsa
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.Store
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.cert.CRL
import java.security.cert.Certificate
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.util.*

/**
 * The util.SignAndTimeStamp class is used to sign PDF(.pdf) with TSA
 */
//Param -> val pdfFile: ByteArray, val cert:Cert?, val tsa:ByteArray?
//ByteArray or File 형태로 반환할 수 있음
class SignAndTimeStamp(val param: PdfSign.Param) : SignatureInterface {
    @Throws(IOException::class)
    override fun sign(inputStream: InputStream): ByteArray {
        return try {
            val certList: MutableList<Certificate?> = ArrayList()
            certList.addAll(param.cert.certificateChain)
            val certStore: Store<*> = JcaCertStore(certList)
            val gen = CMSSignedDataGenerator()
            val cert = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(param.cert.certificate.encoded))
            val sha512Signer = JcaContentSignerBuilder("SHA256WithRSA").build(param.cert.privateKey)
            gen.addSignerInfoGenerator(
                JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build()).build(sha512Signer, X509CertificateHolder(cert))
            )
            gen.addCertificates(certStore)
            val msg = CMSProcessableInputStream(inputStream)
            Tsa().signTimeStamps(gen.generate(msg, false)).encoded
        } catch (e: Exception) {
            e.printStackTrace()
            ByteArray(0)
        }
    }

    @Throws(IOException::class)
    fun signPdf():ByteArrayOutputStream?{
        var doc: PDDocument? = null
        try {
            doc = PDDocument.load(param.pdfFile)
            val out = ByteArrayOutputStream()
            val signature = PDSignature()
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
            signature.signDate = Calendar.getInstance()
            val catalogDict = doc.documentCatalog.cosObject
            catalogDict.isNeedToBeUpdated = true

            // =========================== For LTV Enable ===========================

            //Sorted Certificate 0 = E Entity , 1 = intermediate , 2 = root
            val sortedCertificateChain: Array<Certificate?> = X509Util.SortX509Chain(param.cert.certificateChain, param.cert.certificate)
            param.cert.certificateChain = sortedCertificateChain

            //Assign byte array for storing certificate in DSS Store.
            val certs = arrayOfNulls<ByteArray>(param.cert.certificateChain.size)

            //Assign byte array for storing certificate in DSS Store.
            val crlList: MutableList<CRL> = ArrayList()

            //Fill certificate byte and CRLS
            for (i in param.cert.certificateChain.indices) {
                certs[i] = param.cert.certificateChain[i]!!.encoded
                if (i == param.cert.certificateChain.size - 1) break
                crlList.addAll(DssHelper().readCRLsFromCert(param.cert.certificateChain[i] as X509Certificate))
            }

            //Loop getting All CRLS
            val crls = arrayOfNulls<ByteArray>(crlList.size)
            for (i in crlList.indices) crls[i] = (crlList[i] as X509CRL).encoded

            val certifiates: MutableList<ByteArray?> = Arrays.asList(*certs) //여기 문제일 수도
            val dss = DssHelper().createDssDictionary(certifiates, Arrays.asList(*crls), null)
            catalogDict.setItem(COSName.getPDFName("DSS"), dss)

            // =========================== For LTV Enable =========================== */

            // For big certificate chain
            val signatureOptions = SignatureOptions()
            signatureOptions.preferredSignatureSize = SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2
            doc.addSignature(signature, this, signatureOptions)
            doc.saveIncremental(out) //sign 함수 사용하는 곳!
            return out
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            doc?.close()
        }
        return null
    }

    fun byteArray():ByteArray? = signPdf()?.toByteArray()
//    fun file():File = File(signPdf())?.() ?: error("") //File 객체로 반환하기?
}