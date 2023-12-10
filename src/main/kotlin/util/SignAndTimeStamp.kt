package util

import PdfSign
import Tsa
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.x509.Certificate.*
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
import java.util.*


// ByteArray 또는 File 형태로 반환할 수 있는 PDF 서명 및 타임스탬프 클래스
class SignAndTimeStamp(private val param: PdfSign.Param) : SignatureInterface {

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
            // X.509 인증서 체인의 모든 요소가 addAll
            certList.addAll(param.cert.certificateChain)
            // JcaCertStore는 Bouncy Castle 라이브러리의 클래스로 X.509 인증서를 저장하고 관리하는데 사용됩니다.
            // certList에 있는 X.509 인증서들을 이용하여 certStore 객체를 생성합니다.
            // 이 객체는 나중에 CMS 서명 데이터에 추가될 것입니다. (이상하게 CMS 서명데이터 안에, certStore가 들어가네?)
            val certStore: Store<*> = JcaCertStore(certList)

            // Bouncy Castle 라이브러리를 사용하여 CMS (Cryptographic Message Syntax) 형식의 서명 데이터를 생성하는 과정
            // CMSSignedDataGenerator = CMS 서명 데이터를 생성하는 데 사용
            val gen = CMSSignedDataGenerator()
            // X.509 형식의 인증서를 X509CertificateHolder 형태로 변환하여 저장
            val cert = getInstance(ASN1Primitive.fromByteArray(param.cert.certificate.encoded))
            // SHA-512 알고리즘과 RSA 알고리즘을 사용하여 서명을 생성하는 JcaContentSignerBuilder를 초기화
            val sha512Signer = JcaContentSignerBuilder("SHA256WithRSA").build(param.cert.privateKey)
            // 서명에 필요한 정보를 설정
            gen.addSignerInfoGenerator(
                // 서명 알고리즘, 개인 키, 공개 키 등의 정보가 설정
                JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build()).build(sha512Signer, X509CertificateHolder(cert))
            )
            // CMS 서명에 필요한 인증서 목록을 추가
            gen.addCertificates(certStore)

            // 여기서의 inputStream은 입력값으로 넣은 PDF 파일이다. (서명이 들어갈 대상)
            // PDF 파일이 CMS 데이터를 받아들일 수 있게, 즉 서명이 가능한 inputStream 형태가 되도록 만들어줌
            val msg = CMSProcessableInputStream(inputStream)
            // gen.generate = 실제로 CMS 서명 데이터를 생성
            // 위에서 gen에다가 여러 설정을 주었고 그것을 기반으로 PDF+서명 -> 서명데이터를 만들어냄
            // Tsa().signTimeStamps = 타임스탬프를 추가하고 해당 데이터를 바이트 배열로 반환
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
            // PDF 문서 로드, PD = Portable Document
            // PDDocument = Apache PDFBox 라이브러리에서 제공하는 클래스로, PDF 문서 CRUD
            doc = PDDocument.load(param.pdfFile)
            val out = ByteArrayOutputStream()
            val signature = PDSignature()
            // FILTER_ADOBE_PPKLITE + SUBFILTER_ADBE_PKCS7_DETACHED
            // Adobe의 서명 표준에 따라 생성된 서명임을 나타내고, 서명이 별도의 파일에 저장되어 있음을 나타냅니다.
            // PDF 문서에서 서명에 사용되는 알고리즘을 지정합니다. - Adobe의 서명 표준
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
            // 서명 값을 PDF 외부에 저장하고 서명의 일부로써 참조할 수 있도록 하는 서명 방식
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)

            signature.signDate = Calendar.getInstance()
            // PDF 문서의 구조는 카탈로그 객체를 중심으로 구성됩니다.
            val catalogDict = doc.documentCatalog.cosObject
            // 카탈로그 객체를 업데이트해야 함을 표시합니다. 이는 서명을 추가하고 문서를 저장할 때 필요한 작업입니다.
            catalogDict.isNeedToBeUpdated = true

            // =========================== For LTV Enable ===========================
            // LTV는 Long-Term Validation의 약어로, PDF 서명의 장기 유효성을 보장하기 위한 기술입니다.

            // 인증서 체인 정렬 (막내가 첫번째이고, 발급자가 제일 마지막)
            val sortedCertificateChain: Array<Certificate?> = X509Util.sortX509Chain(param.cert.certificateChain, param.cert.certificate)
            param.cert.certificateChain = sortedCertificateChain

            // 사용된 인증서 + CRL(Certificate Revocation List) = DSS(Document Security Store)
            // CRL을 참고하여 해당 인증서가 폐지되었는지 여부를 확인
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

            // PDF 문서에 DSS(Document Security Store) 딕셔너리를 추가하는 부분
            // Certificate와 CRL 데이터를 DSS 딕셔너리로 변환
            val certificates: MutableList<ByteArray?> = Arrays.asList(*certs)
            val dss = DssHelper().createDssDictionary(certificates, Arrays.asList(*crls), null)
            //DSS 딕셔너리를 PDF 문서의 Catalog에 추가합니다. 이렇게 함으로써,
            //PDF 문서에 LTV를 활성화하는 데 필요한 인증서 및 CRL 정보가 포함되어 장기적인 서명 유효성 검증을 가능케 합니다.
            catalogDict.setItem(COSName.getPDFName("DSS"), dss)

            // =========================== For LTV Enable =========================== */

            // 큰 인증서 체인을 위한 서명 옵션 설정
            // 서명의 크기를 두 배로 설정함으로써, 서명 영역에 더 많은 정보를 포함시킬 수 있게 됩니다.
            // 일반적으로 큰 인증서 체인을 다루거나 서명에 추가 정보를 담아야 하는 경우에 사용됩니다.
            val signatureOptions = SignatureOptions()
            signatureOptions.preferredSignatureSize = SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2

            // 서명 추가 및 PDF 저장
            // addSignature 함수에서 내부적으로 sign() 함수가 실행된다.
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
