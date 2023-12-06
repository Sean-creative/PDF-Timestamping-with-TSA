package util

import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.tsp.TimeStampToken
import org.bouncycastle.util.Selector
import org.bouncycastle.util.Store
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.*
import java.util.*
import javax.security.auth.x500.X500Principal

object X509Util {
    @Throws(KeyStoreException::class, NoSuchAlgorithmException::class, CertificateException::class, IOException::class)
    fun X509FromToken(token: TimeStampToken): X509Certificate? {
        val cs: Store<*> = token.certificates
        val c = cs.getMatches(X509CRLSelector() as Nothing) as ArrayList<X509CertificateHolder> //이부분 문제가 있을 수도 있음
        val certStore = arrayOfNulls<X509Certificate>(c.size)
        for (i in c.indices) {
            val certFactory = CertificateFactory.getInstance("X.509")
            val `in`: InputStream = ByteArrayInputStream(c[i].encoded)
            val certTemp = certFactory.generateCertificate(`in`) as X509Certificate
            certStore[i] = certTemp
        }
        val orderedStore = SortX509Chain(certStore)
        return orderedStore[0] ?: return null
    }

    fun SortX509Chain(chain: Array<X509Certificate?>): Array<X509Certificate?> {
        if (chain[0]!!.subjectDN != chain[0]!!.issuerDN) {
            return chain
        }
        val chainLenght = chain.size
        val newChain = arrayOfNulls<X509Certificate>(chainLenght)
        var foundRoot = false
        val certMap = HashMap<X500Principal, X509Certificate?>()
        for (i in 0 until chainLenght) {
            val issuer = chain[i]!!.issuerX500Principal
            val subject = chain[i]!!.subjectX500Principal
            certMap[issuer] = chain[i]
            if (issuer == subject) {
                newChain[chainLenght - 1] = chain[i]
                foundRoot = true
            }
        }
        if (!foundRoot) return chain
        for (i in chainLenght - 2 downTo 0) {
            newChain[i] = certMap[newChain[i + 1]!!.subjectX500Principal]
        }
        return newChain
    }

    fun SortX509Chain(chain: List<X509Certificate?>): List<X509Certificate?> {
        var sorted: List<X509Certificate?>
        var chainArr = chain.stream().toArray() as Array<X509Certificate?>
        val sortedChain = SortX509Chain(chainArr)
        sorted = Arrays.asList(*sortedChain)
        return sorted
    }

    fun SortX509Chain(certificateChain: Array<Certificate?>, signerCert: Certificate): Array<Certificate?> {
        val signCertificate = signerCert as X509Certificate
        val unsorted: MutableList<X509Certificate> = ArrayList()
        for (i in certificateChain.indices) {
            val currentX509cert = certificateChain[i] as X509Certificate
            unsorted.add(currentX509cert)
        }
        val X509Sorted = SortX509Chain(unsorted, signCertificate)
        val certSorted = arrayOfNulls<Certificate>(certificateChain.size)
        for (i in certificateChain.indices) {
            certSorted[i] = X509Sorted[i] as Certificate
        }
        return certSorted
    }

    fun SortX509Chain(chain: List<X509Certificate?>, signerCert: X509Certificate): List<X509Certificate> {
        val sorted: MutableList<X509Certificate> = ArrayList()
        sorted.add(signerCert)
        var cert = signerCert
        for (i in 0 until chain.size - 1) {
            val issuer = cert.issuerX500Principal
            val subject = cert.subjectX500Principal            // If last cert in sorted chain is root, sorting is done
            if (issuer != subject) {
                for (j in chain.indices) {
                    val issuerCert = chain[j]
                    val subjectOfIssuer = issuerCert!!.subjectX500Principal
                    if (issuer == subjectOfIssuer) {
                        sorted.add(issuerCert)
                        cert = issuerCert
                    }
                }
            }
        }
        return sorted
    }
}