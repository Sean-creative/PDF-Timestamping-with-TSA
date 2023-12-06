package util

import org.apache.pdfbox.io.IOUtils
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSTypedData
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

internal class CMSProcessableInputStream(private val contentType: ASN1ObjectIdentifier, private val `in`: InputStream) : CMSTypedData {
    constructor(`is`: InputStream) : this(ASN1ObjectIdentifier(CMSObjectIdentifiers.data.id), `is`) {}

    override fun getContent(): Any {
        return `in`
    }

    @Throws(IOException::class, CMSException::class)
    override fun write(out: OutputStream) {        // read the content only one time
        IOUtils.copy(`in`, out)
        `in`.close()
    }

    override fun getContentType(): ASN1ObjectIdentifier {
        return contentType
    }
}