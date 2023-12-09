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


// ByteArray 또는 File 형태로 반환할 수 있는 PDF 서명 및 타임스탬프 클래스
class SignAndTimeStamp(val param: PdfSign.Param) : SignatureInterface {

    /**
     * 입력 스트림을 사용하여 서명을 생성하고 타임스탬프를 적용합니다.
     *
     * @param inputStream 서명 대상의 입력 스트림
     * @return 생성된 서명과 타임스탬프의 데이터 바이트 배열
     */
    @Throws(IOException::class)
    override fun sign(inputStream: InputStream): ByteArray {
        return try {
            // 인증서 목록 설정
            val certList: MutableList<Certificate?> = ArrayList()
            certList.addAll(param.cert.certificateChain)
            val certStore: Store<*> = JcaCertStore(certList)

            // CMS 서명 데이터 생성
            val gen = CMSSignedDataGenerator()
            val cert = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(param.cert.certificate.encoded))
            val sha512Signer = JcaContentSignerBuilder("SHA256WithRSA").build(param.cert.privateKey)
            gen.addSignerInfoGenerator(
                JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build()).build(sha512Signer, X509CertificateHolder(cert))
            )
            gen.addCertificates(certStore)

            // 서명 및 타임스탬프 생성
            val msg = CMSProcessableInputStream(inputStream)
            Tsa().signTimeStamps(gen.generate(msg, false)).encoded
        } catch (e: Exception) {
            e.printStackTrace()
            ByteArray(0)
        }
    }

    /**
     * PDF를 서명하고 LTV 활성화를 위해 필요한 설정을 수행한 뒤, 바이트 배열로 반환합니다.
     *
     * @return 서명된 PDF의 데이터를 포함하는 ByteArrayOutputStream
     */
    @Throws(IOException::class)
    fun signPdf(): ByteArrayOutputStream? {
        var doc: PDDocument? = null
        try {
            // PDF 문서 로드
            doc = PDDocument.load(param.pdfFile)
            val out = ByteArrayOutputStream()
            val signature = PDSignature()
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
            signature.signDate = Calendar.getInstance()
            val catalogDict = doc.documentCatalog.cosObject
            catalogDict.isNeedToBeUpdated = true

            // =========================== For LTV Enable ===========================

            // 인증서 체인 정렬
            val sortedCertificateChain: Array<Certificate?> = X509Util.SortX509Chain(param.cert.certificateChain, param.cert.certificate)
            param.cert.certificateChain = sortedCertificateChain

            // DSS 스토어에 저장할 인증서 바이트 배열 할당
            val certs = arrayOfNulls<ByteArray>(param.cert.certificateChain.size)

            // DSS 스토어에 저장할 CRL 목록
            val crlList: MutableList<CRL> = ArrayList()

            // 인증서와 CRL 데이터 추출
            for (i in param.cert.certificateChain.indices) {
                certs[i] = param.cert.certificateChain[i]!!.encoded
                if (i == param.cert.certificateChain.size - 1) break
            }

            // CRL 데이터 추출 후 배열로 변환
            val crls = arrayOfNulls<ByteArray>(crlList.size)
            for (i in crlList.indices) crls[i] = (crlList[i] as X509CRL).encoded

            // Certificate와 CRL 데이터를 DSS 딕셔너리로 변환
            val certificates: MutableList<ByteArray?> = Arrays.asList(*certs)
            val dss = DssHelper().createDssDictionary(certificates, Arrays.asList(*crls), null)
            catalogDict.setItem(COSName.getPDFName("DSS"), dss)

            // =========================== For LTV Enable =========================== */

            // 큰 인증서 체인을 위한 서명 옵션 설정
            val signatureOptions = SignatureOptions()
            signatureOptions.preferredSignatureSize = SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2

            // 서명 추가 및 PDF 저장
            doc.addSignature(signature, this, signatureOptions)
            doc.saveIncremental(out)

            return out
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            doc?.close()
        }
        return null
    }

    /**
     * 서명된 PDF를 바이트 배열로 반환합니다.
     *
     * @return 서명된 PDF의 데이터를 포함하는 ByteArray
     */
    fun byteArray(): ByteArray? = signPdf()?.toByteArray()
}
