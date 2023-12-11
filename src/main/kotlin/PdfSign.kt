import util.SignAndTimeStamp
import java.io.File
import java.net.URL
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.*

object PdfSign {
    private const val KEYSTORE_TYPE = "PKCS12"

    lateinit var cert: Cert
    lateinit var date: Date

    // Certificate 정보를 담는 데이터 클래스
    class Cert(val privateKey: PrivateKey, val certificate: Certificate, var certificateChain: Array<Certificate?>)

    // PDF 서명에 필요한 파라미터를 담는 데이터 클래스
    class Param(val pdfFile: ByteArray, val cert: Cert, val date: String?)

    // P12 파일을 기반으로 개인키도 추출하고, 인증서도 넣어서 Certificate 객체 생성하는 함수
    private fun cert(p12File: String, password: String, isUrl: Boolean = false): Cert? {
        val pwCharArray = password.toCharArray()
        //KeyStore는 Java에서 암호화된 개인 키, 디지털 인증서 및 인증서 체인을 저장하는 데 사용되는 클래스
        //PKCS #12 형식의 키 저장소 가져옴
        val keystore = KeyStore.getInstance(KEYSTORE_TYPE)

        // P12 파일을 URL에서 읽을지 파일에서 읽을지 선택
        if (isUrl) keystore.load(URL(p12File).openStream(), pwCharArray)
        else keystore.load(File(p12File).inputStream(), pwCharArray)

        //키 저장소에 포함된 모든 키 엔트리(개인 키 및 인증서 쌍)의 별칭(alias) 목록을 얻습니다
        val aliases = keystore.aliases()
        //단 여러개의 별칭이 있어도 첫번째 별칭만 처리함
        if (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            return Cert(
                keystore.getKey(alias, pwCharArray) as PrivateKey,
                keystore.getCertificate(alias),
                keystore.getCertificateChain(alias)
            )
        }
        return null
    }

    // PDF 파일을 서명하여 바이트 배열로 반환하는 함수
    private fun signByteArray(param: Param): ByteArray? {
        val calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        // 날짜가 주어진 경우 UTC로 변환하여 설정
        param.date?.also {
            val d = it.split(' ')
            if (d.size == 2) {
                val ymd = d.first().split('-')
                val hmi = d.last().split(':')
                calendar.set(ymd[0].toInt(), ymd[1].toInt() - 1, ymd[2].toInt(), hmi[0].toInt(), hmi[1].toInt(), hmi[2].toInt())
            }
        }
        date = calendar.time

        // SignAndTimeStamp 객체를 통해 PDF 서명 수행
        return SignAndTimeStamp(param).byteArray()
    }

    // main 함수
    @JvmStatic
    fun main(args: Array<String>) {
        // PFX 파일을 기반으로 Cert 객체 생성
        cert = cert("seanTest.pfx", "0000") ?: error("cert error")

        try {
            // 현재 UTC 시간을 가져오기
            val currentUTCTime = LocalDateTime.now(ZoneOffset.UTC)

            // DateTimeFormatter를 사용하여 원하는 형식으로 포맷팅
            val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")

            // 포맷팅된 UTC 시간 출력
            val formattedUTCTime = currentUTCTime.format(formatter)
            println("현재 UTC 시간: $formattedUTCTime")

            // PDF 파일 서명 수행
            signByteArray(
                // date는 원하는 시간을 하드코딩 해도 됩니다. ex) 2023-12-07 01:22:22
                // 단, UTC 기준으로 넣어야하기 때문에 PDF 입장에서 +9시간을 했을 때 미래시간으로 인식하는 오류를 조심하세요.
//                Param(File("sample.pdf").readBytes(), cert, formattedUTCTime)
                Param(File("sample.pdf").readBytes(), cert, formattedUTCTime)
            )?.also {
                // 서명된 PDF 파일을 새로운 파일로 저장
                File("sample_signed.pdf").writeBytes(it)
            } ?: error("file error")
        } catch (e: Throwable) {
            // 예외 발생 시 에러 메시지 출력
            println(e.localizedMessage)
        }
    }
}
