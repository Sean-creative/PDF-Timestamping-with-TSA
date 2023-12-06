package util

import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.cos.COSStream
import sun.security.x509.*
import java.io.*
import java.net.URI
import java.security.cert.CRL
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate

class DssHelper {
    @Throws(IOException::class)
    fun createDssDictionary(certifiates: Iterable<ByteArray?>?, crls: Iterable<ByteArray?>?, ocspResponses: Iterable<ByteArray?>?): COSDictionary {
        val dssDictionary = COSDictionary()
        dssDictionary.isNeedToBeUpdated = true
        dssDictionary.setName(COSName.TYPE, "DSS")
        if (certifiates != null) dssDictionary.setItem(COSName.getPDFName("Certs"), createArray(certifiates))
        if (crls != null) dssDictionary.setItem(COSName.getPDFName("CRLs"), createArray(crls))
        if (ocspResponses != null) dssDictionary.setItem(COSName.getPDFName("OCSPs"), createArray(ocspResponses))
        return dssDictionary
    }

    @Throws(IOException::class)
    fun createArray(datas: Iterable<ByteArray?>?): COSArray {
        val array = COSArray()
        array.isNeedToBeUpdated = true
        if (datas != null) {
            for (data in datas) array.add(createStream(data))
        }
        return array
    }

    @Throws(IOException::class)
    fun createStream(data: ByteArray?): COSStream {        //RandomAccessBuffer storage = new RandomAccessBuffer();
        val stream = COSStream()
        stream.isNeedToBeUpdated = true
        val unfilteredStream = stream.createRawOutputStream()
        unfilteredStream.write(data)
        unfilteredStream.flush()
        unfilteredStream.close()
        return stream
    }

    @Throws(Exception::class)
    fun readCRLsFromCert(cert: X509Certificate?): List<CRL> {
        val crls: MutableList<CRL> = ArrayList()
//        val ext = X509CertImpl.toImpl(cert).crlDistributionPointsExtension ?: return crls
//        for (o in ext[CRLDistributionPointsExtension.POINTS] as List<DistributionPoint>) {
//            val names = o.fullName
//            if (names != null) {
//                for (name in names.names()) {
//                    if (name.type == GeneralNameInterface.NAME_URI) {
//                        val uriName = name.name as URIName
//                        for (crl in loadCRLs(uriName.name)!!) {
//                            if (crl is X509CRL) {
//                                crls.add(crl)
//                            }
//                        }
//                        break // Different name should point to same CRL
//                    }
//                }
//            }
//        }
        return crls
    }

    @Throws(Exception::class)
    fun loadCRLs(src: String?): Collection<CRL>? {
        var `in`: InputStream? = null
        var uri: URI? = null
        if (src == null) {
            `in` = System.`in`
        } else {
            try {
                uri = URI(src)
                if (uri.scheme == "ldap") { // No input stream for LDAP
                } else {
                    `in` = uri.toURL().openStream()
                }
            } catch (e: Exception) {
                `in` = try {
                    FileInputStream(src)
                } catch (e2: Exception) {
                    if (uri == null || uri.scheme == null) {
                        throw e2 // More likely a bare file path
                    } else {
                        throw e // More likely a protocol or network problem
                    }
                }
            }
        }
        return if (`in` != null) {
            try { // Read the full stream before feeding to X509Factory,
                // otherwise, keytool -gencrl | keytool -printcrl
                // might not work properly, since -gencrl is slow
                // and there's no data in the pipe at the beginning.
                val bout = ByteArrayOutputStream()
                val b = ByteArray(4096)
                while (true) {
                    val len = `in`.read(b)
                    if (len < 0) break
                    bout.write(b, 0, len)
                }
                CertificateFactory.getInstance("X509").generateCRLs(
                    ByteArrayInputStream(bout.toByteArray())
                )
            } finally {
                if (`in` !== System.`in`) {
                    `in`.close()
                }
            }
        } else {    // must be LDAP, and uri is not null
            var path = uri!!.path
            if (path[0] == '/') path = path.substring(1) //            LDAPCertStoreHelper h = new LDAPCertStoreHelper();
            //            CertStore s = h.getCertStore(uri);
            //            X509CRLSelector sel =
            //                    h.wrap(new X509CRLSelector(), null, path);
            //            return s.getCRLs(sel);
            null
        }
    }
}