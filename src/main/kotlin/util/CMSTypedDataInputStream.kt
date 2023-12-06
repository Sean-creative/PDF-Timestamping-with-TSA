package util

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSTypedData
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

internal class CMSTypedDataInputStream(var `in`: InputStream) : CMSTypedData {
    override fun getContentType(): ASN1ObjectIdentifier {
        return PKCSObjectIdentifiers.data
    }

    override fun getContent(): Any {
        return `in`
    }

    @Throws(IOException::class, CMSException::class)
    override fun write(out: OutputStream) {
        val buffer = ByteArray(8 * 1024)
        var read: Int
        while (`in`.read(buffer).also { read = it } != -1) {
            out.write(buffer, 0, read)
        }
        `in`.close()
    }
}