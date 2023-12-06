import com.itextpdf.html2pdf.ConverterProperties
import com.itextpdf.html2pdf.HtmlConverter
import com.itextpdf.kernel.geom.PageSize
import com.itextpdf.kernel.pdf.PdfDocument
import com.itextpdf.kernel.pdf.PdfReader
import com.itextpdf.kernel.pdf.PdfWriter
import org.apache.pdfbox.io.IOUtils
import util.SignAndTimeStamp
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.URL
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.*
import kotlin.random.Random

object Pdf {
    private val uuid = "3b99e3e0-7598-11e8-90be-95472fb3ecbd".split('-').map { v -> v.length }
    fun uuid(sep: String = "-") = uuid.joinToString(separator = sep) { Random.nextLong(0x100000000000L, 0xffffffffffffL).toString(16).substring(0, it) }

    fun htmlConverter(html: String): ByteArrayOutputStream {
        val outputStream = ByteArrayOutputStream()
        HtmlConverter.convertToPdf(html, outputStream)
        return outputStream
    }

    fun htmlToPdf(basePath: String, toPdf: PdfDocument, html: String, isVertical: Boolean = true): String {
        var fileUrl = ""
        val pdfDocument = if (isVertical) {
            val outputStream = ByteArrayOutputStream()
            HtmlConverter.convertToPdf(html, outputStream)
            PdfDocument(PdfReader(ByteArrayInputStream(outputStream.toByteArray())))
        } else {
            fileUrl = "$basePath/${uuid("")}.pdf"
            val doc = PdfDocument(PdfWriter(fileUrl))
            doc.defaultPageSize = PageSize.A4.rotate()
            HtmlConverter.convertToPdf(html, doc, ConverterProperties())
            PdfDocument(PdfReader(fileUrl))
        }

        for (i in 1..pdfDocument.numberOfPages) {
            val page = pdfDocument.getPage(i).copyTo(toPdf)
            toPdf.addPage(page)
        }

        pdfDocument.close()
        return fileUrl
    }

    fun urlToBase64(fileUrl: String): String {
        val url = URL(fileUrl)
        val iss = url.openStream()
        val bytes = IOUtils.toByteArray(iss)
        return "data:image/png;base64,${Base64.getEncoder().encodeToString(bytes)}"
    }
}