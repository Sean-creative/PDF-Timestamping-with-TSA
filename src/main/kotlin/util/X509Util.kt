package util

import java.security.cert.Certificate
import java.security.cert.X509Certificate

object X509Util {

    /**
     * X.509 인증서 체인을 발급자 기준으로 정렬합니다.
     *
     * @param certificateChain 정렬되지 않은 X.509 인증서 체인입니다.
     * @param signerCert 정렬에 사용되는 서명자 인증서입니다.
     * @return 정렬된 X.509 인증서 체인입니다.
     */
    fun sortX509Chain(certificateChain: Array<Certificate?>, signerCert: Certificate): Array<Certificate?> {
        val signCertificate = signerCert as X509Certificate
        val unsorted: MutableList<X509Certificate> = mutableListOf()

        // 인증서 체인을 X.509 인증서의 목록으로 변환합니다.
        for (i in certificateChain.indices) {
            val currentX509cert = certificateChain[i] as X509Certificate
            unsorted.add(currentX509cert)
        }

        // 목록의 X.509 인증서를 정렬합니다.
        val x509Sorted = sortX509Chain(unsorted, signCertificate)

        // 정렬된 목록을 다시 Certificate 배열로 변환합니다.
        val certSorted = arrayOfNulls<Certificate>(certificateChain.size)
        for (i in certificateChain.indices) {
            certSorted[i] = x509Sorted[i] as Certificate
        }

        return certSorted
    }

    /**
     * X.509 인증서 체인을 발급자 기준으로 정렬합니다.
     *
     * @param chain 정렬되지 않은 X.509 인증서 체인입니다.
     * @param signerCert 정렬에 사용되는 서명자 인증서입니다.
     * @return 정렬된 X.509 인증서 체인입니다.
     */
    private fun sortX509Chain(chain: List<X509Certificate?>, signerCert: X509Certificate): List<X509Certificate> {
        val sorted: MutableList<X509Certificate> = ArrayList()
        sorted.add(signerCert)
        var cert = signerCert

        // 체인을 반복하여 정렬된 목록에 인증서를 찾아 추가합니다.
        for (i in 0 until chain.size - 1) {
            val issuer = cert.issuerX500Principal
            val subject = cert.subjectX500Principal

            // 정렬된 체인의 마지막 인증서가 루트이면 정렬이 완료됩니다.
            if (issuer != subject) {
                for (j in chain.indices) {
                    val issuerCert = chain[j]
                    val subjectOfIssuer = issuerCert!!.subjectX500Principal

                    // 발급자가 일치하는 인증서를 찾아 정렬된 목록에 추가합니다.
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