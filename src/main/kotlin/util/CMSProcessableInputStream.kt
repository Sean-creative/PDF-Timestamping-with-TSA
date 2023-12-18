package util

import org.apache.pdfbox.io.IOUtils
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSTypedData
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * CMS (Cryptographic Message Syntax)를 처리 가능한 입력 스트림을 제공하는 클래스.
 *
 * @property contentType CMS 데이터의 유형을 나타내는 ASN1ObjectIdentifier
 * @property `in` 처리할 입력 스트림
 * @constructor 주어진 contentType 및 입력 스트림으로 CMSProcessableInputStream을 초기화합니다.
 */
internal class CMSProcessableInputStream(private val contentType: ASN1ObjectIdentifier, private val `in`: InputStream) : CMSTypedData {

    /**
     * 주어진 입력 스트림으로 CMSProcessableInputStream을 초기화합니다.
     *
     * @param `is` 처리할 입력 스트림
     */
    constructor(`is`: InputStream) : this(ASN1ObjectIdentifier(CMSObjectIdentifiers.data.id), `is`)

    /**
     * CMSTypedData에서 데이터를 가져옵니다.
     *
     * @return 입력 스트림
     */
    override fun getContent(): Any {
        return `in`
    }

    /**
     * 출력 스트림으로 데이터를 쓰기 위한 메서드입니다.
     *
     * @param out 출력할 스트림
     * @throws IOException 스트림 쓰기 중 발생 가능한 IO 예외
     * @throws CMSException CMS 예외
     */
    @Throws(IOException::class, CMSException::class)
    override fun write(out: OutputStream) { // 컨텐츠를 한 번만 읽음
        IOUtils.copy(`in`, out)
        `in`.close()
    }

    /**
     * 현재 CMSTypedData의 유형을 나타내는 ASN1ObjectIdentifier를 가져옵니다.
     *
     * @return CMS 데이터의 유형을 나타내는 ASN1ObjectIdentifier
     */
    override fun getContentType(): ASN1ObjectIdentifier {
        return contentType
    }
}
