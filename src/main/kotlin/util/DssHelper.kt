package util

import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.cos.COSStream
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream

/**
 * DSS(Digital Signature Service)에 관련된 도우미 클래스.
 */
class DssHelper {

    /**
     * Certificates, CRLs, OCSP Responses를 포함하는 DSS Dictionary를 생성합니다.
     *
     * @param certificates 서명에 사용되는 인증서의 바이트 배열 목록
     * @param crls 서명에 사용되는 CRL(인증서 폐기 목록)의 바이트 배열 목록
     * @param ocspResponses 서명에 사용되는 OCSP(Online Certificate Status Protocol) 응답의 바이트 배열 목록
     * @return 생성된 DSS Dictionary
     * @throws IOException
     */
    @Throws(IOException::class)
    fun createDssDictionary(certificates: Iterable<ByteArray?>?, crls: Iterable<ByteArray?>?, ocspResponses: Iterable<ByteArray?>?): COSDictionary {
        val dssDictionary = COSDictionary()
        dssDictionary.isNeedToBeUpdated = true
        dssDictionary.setName(COSName.TYPE, "DSS")
        if (certificates != null) dssDictionary.setItem(COSName.getPDFName("Certs"), createArray(certificates))
        if (crls != null) dssDictionary.setItem(COSName.getPDFName("CRLs"), createArray(crls))
        if (ocspResponses != null) dssDictionary.setItem(COSName.getPDFName("OCSPs"), createArray(ocspResponses))
        return dssDictionary
    }

    /**
     * 바이트 배열 목록을 포함하는 COSArray를 생성합니다.
     *
     * @param datas 바이트 배열 목록
     * @return 생성된 COSArray
     * @throws IOException
     */
    @Throws(IOException::class)
    fun createArray(datas: Iterable<ByteArray?>?): COSArray {
        val array = COSArray()
        array.isNeedToBeUpdated = true
        if (datas != null) {
            for (data in datas) array.add(createStream(data))
        }
        return array
    }

    /**
     * 바이트 배열을 포함하는 COSStream을 생성합니다.
     *
     * @param data 바이트 배열
     * @return 생성된 COSStream
     * @throws IOException
     */
    @Throws(IOException::class)
    fun createStream(data: ByteArray?): COSStream {
        val stream = COSStream()
        stream.isNeedToBeUpdated = true
        val unfilteredStream = stream.createRawOutputStream()
        unfilteredStream.write(data)
        unfilteredStream.flush()
        unfilteredStream.close()
        return stream
    }
}
