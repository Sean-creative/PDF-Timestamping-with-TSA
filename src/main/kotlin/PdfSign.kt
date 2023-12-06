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
    const val KEYSTORE_TYPE = "PKCS12"

    lateinit var cert: Cert
    lateinit var date: Date

    class Cert(val privateKey: PrivateKey, val certificate: Certificate, var certificateChain: Array<Certificate?>)
    class Param(val pdfFile: ByteArray, val cert: Cert, val date: String?)

    private fun cert(p12File: String, password: String, isUrl: Boolean = false): Cert? {
        val pwCharArray = password.toCharArray()
        val keystore = KeyStore.getInstance(KEYSTORE_TYPE)
        if (isUrl) keystore.load(URL(p12File).openStream(), pwCharArray)
        else keystore.load(File(p12File).inputStream(), pwCharArray)
        val aliases = keystore.aliases()
        if (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            return Cert(
                keystore.getKey(alias, pwCharArray) as PrivateKey, keystore.getCertificate(alias), keystore.getCertificateChain(alias)
            )
        }
        return null
    }

    private fun signByteArray(param: Param): ByteArray? {
        cert = param.cert
        val calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        param.date?.also {
            val d = it.split(' ')
            if (d.size == 2) {
                val ymd = d.first().split('-')
                val hmi = d.last().split(':')
                calendar.set(ymd[0].toInt(), ymd[1].toInt() - 1, ymd[2].toInt(), hmi[0].toInt(), hmi[1].toInt(), hmi[2].toInt())
            }
        }

        date = calendar.time
        return SignAndTimeStamp(param).byteArray()
    }

    //date에는 원하는 날짜 넣으시면 됩니다.
    @JvmStatic
    fun main(args: Array<String>) {
        cert = cert("seanTest.pfx", "0000") ?: error("cert error")
        try { // 현재 UTC 시간을 가져오기
            val currentUTCTime = LocalDateTime.now(ZoneOffset.UTC) // DateTimeFormatter를 사용하여 원하는 형식으로 포맷팅
            val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss") // 포맷팅된 UTC 시간 출력
            val formattedUTCTime = currentUTCTime.format(formatter)
            println("현재 UTC 시간: $formattedUTCTime")
            signByteArray(
                //date는 원하는 시간을 하드코딩 해도 됩니다. ex) 2023-12-07 01:22:22
                // 단, UTC기준으로 넣어야하기 때문에 PDF 입장에서 +9시간을 했을 때 미래시간으로 인식하는 오류를 조심하세요.
                Param(File("sample.pdf").readBytes(), cert, formattedUTCTime)
            )?.also {
                File("sample_signed.pdf").writeBytes(it)
            } ?: error("file error")
        } catch (e: Throwable) {
            println(e.localizedMessage)
        }
    }
}