package netscope.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

data class TlsInfo(
    val host: String,
    val port: Int,
    val ok: Boolean,
    val ms: Long,
    val protocol: String = "",
    val cipherSuite: String = "",
    val alpn: String = "",
    val sni: String = "",
    val subject: String = "",
    val issuer: String = "",
    val issuerOrg: String = "",
    val notBefore: String = "",
    val notAfter: String = "",
    val serial: String = "",
    val sigAlg: String = "",
    val pubKey: String = "",
    val san: List<String> = emptyList(),
    val chainLength: Int = 0,
    val leaf: X509Certificate? = null,
    val publiclyTrusted: Boolean? = null,
    val trustError: String = "",
    val daysLeft: Long = 0,
    val error: String = "",
    val netError: NetError = NetError.NONE
) {
    fun short(): String = when {
        !ok -> "${netError.symbol()}${if (error.isNotBlank()) " ($error)" else ""}"
        else -> "$protocol ${if (alpn.isNotBlank()) "($alpn) " else ""}<$issuer>"
    }
}

object Mitm {
    /** Маркеры, по которым сертификат однозначно выдаёт локальный перехват трафика. */
    val markers: List<String> = listOf(
        "mitmproxy", "mitm", "charles", "fiddler", "burp", "zaproxy", "owasp zap",
        "bluestacks", "whistle", "http debugger", "fiddlerweb", "proxyman", "insomnia",
        "kaspersky", "avast", "avira", "eset", "norton", "symantec", "mcafee", "bitdefender",
        "adguard", "pihole", "nextdns", "adguard home", "blocky", "unbound", "dnsmasq",
        "palo alto", "forcepoint", "symantec proxy", "zscaler", "netskope", "cato networks",
        "fiddlelite", "webdebugger", "http proxy", "telerik", "spoon", "requestly",
        "sandbox", "denyall", "sugarnproxy", "glassdoor", "tigera", "calico", "gvisor",
        "istio", "envoy mitm", "squid", "tinyproxy", "tint", "gost", "frp", "ngrok"
    )

    private val vendorCn = Regex("CN=([^,]+)")
    private val orgO = Regex("O=([^,]+)")

    fun matches(text: String): List<String> {
        val t = text.lowercase(Locale.ROOT)
        return markers.filter { t.contains(it) }
    }

    fun vendorOf(cert: X509Certificate?): String {
        if (cert == null) return ""
        val d = cert.issuerX500Principal.name
        orgO.find(d)?.groupValues?.get(1)?.let { return it.trim() }
        vendorCn.find(d)?.groupValues?.get(1)?.let { return it.trim() }
        return d
    }

    fun sha256(cert: X509Certificate): String =
        MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString(":") { "%02x".format(it) }
}

object Tls {
    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private val dateFmt = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).apply { timeZone = TimeZone.getTimeZone("UTC") }

    private fun context(trustAnyone: Boolean): SSLContext =
        SSLContext.getInstance("TLS").apply {
            init(null, if (trustAnyone) arrayOf(trustAll) else null, SecureRandom())
        }

    suspend fun probe(
        host: String,
        port: Int = 443,
        timeoutMs: Int = 4000,
        forcedProtocol: String? = null,
        alpn: List<String> = listOf("h2", "http/1.1"),
        sniOverride: String? = null,
        trustAnyone: Boolean = true,
        verifyHostname: Boolean = true,
        followIp: Boolean = false
    ): TlsInfo = withContext(Dispatchers.IO) {
        val t0 = nanoMs()
        val sni = sniOverride ?: host
        var sock: SSLSocket? = null
        try {
            val ctx = context(trustAnyone)
            val raw = ctx.socketFactory.createSocket() as SSLSocket
            sock = raw
            val params = raw.sslParameters
            params.protocols = if (forcedProtocol != null) arrayOf(forcedProtocol) else arrayOf("TLSv1.3", "TLSv1.2")
            if (alpn.isNotEmpty()) params.applicationProtocols = alpn.toTypedArray()
            if (sni.isNotBlank() && !sni.contains(" ")) runCatching { params.serverNames = listOf(SNIHostName(sni)) }
            params.endpointIdentificationAlgorithm = if (verifyHostname) "HTTPS" else null
            params.cipherSuites = null
            raw.sslParameters = params
            raw.connect(java.net.InetSocketAddress(host, port), timeoutMs)
            raw.soTimeout = timeoutMs
            raw.startHandshake()
            val ms = nanoMs() - t0
            val session = raw.session
            val derChain = session.peerCertificates.map { it.encoded }
            val cf = CertificateFactory.getInstance("X.509")
            val chain = derChain.mapNotNull { runCatching { cf.generateCertificate(java.io.ByteArrayInputStream(it)) as X509Certificate }.getOrNull() }
            val leaf = chain.firstOrNull()
            var publicOk: Boolean? = null
            var trustErr = ""
            if (chain.isNotEmpty()) {
                publicOk = try {
                    checkTrusted(chain)
                    true
                } catch (e: Throwable) {
                    trustErr = e.message?.lineSequence()?.firstOrNull()?.take(140) ?: e::class.java.simpleName
                    false
                }
            }
            val san = leaf?.let { l ->
                runCatching {
                    l.subjectAlternativeNames.orEmpty().mapNotNull { entry ->
                        val list = entry as? List<*> ?: return@mapNotNull null
                        val v = list.getOrNull(1)?.toString() ?: return@mapNotNull null
                        val t = entry.firstOrNull()
                        if (t == 2) "DNS:$v" else "$t:$v"
                    }
                }.getOrDefault(emptyList())
            } ?: emptyList()
            val notAfter = leaf?.notAfter?.let { dateFmt.format(it) } ?: ""
            val days = if (leaf != null) (leaf.notAfter.time - System.currentTimeMillis()) / 86_400_000 else 0
            TlsInfo(
                host = host, port = port, ok = true, ms = ms,
                protocol = session.protocol, cipherSuite = session.cipherSuite,
                alpn = raw.applicationProtocol ?: "",
                sni = sni,
                subject = leaf?.subjectX500Principal?.name?.take(200) ?: "",
                issuer = leaf?.issuerX500Principal?.name?.take(200) ?: "",
                issuerOrg = Mitm.vendorOf(leaf),
                notBefore = leaf?.notBefore?.let { dateFmt.format(it) } ?: "",
                notAfter = notAfter,
                serial = leaf?.serialNumber?.toString(16)?.uppercase() ?: "",
                sigAlg = leaf?.sigAlgName ?: "",
                pubKey = leaf?.publicKey?.algorithm ?: "",
                san = san,
                chainLength = chain.size,
                leaf = leaf,
                publiclyTrusted = publicOk,
                trustError = trustErr,
                daysLeft = days
            )
        } catch (e: Throwable) {
            TlsInfo(host, port, false, nanoMs() - t0, error = e.message ?: e::class.java.simpleName, netError = classify(e))
        } finally {
            runCatching { sock?.close() }
        }
    }

    /** Тот же хендшейк, но с проверкой публичного доверия (без MITM-исключений). */
    fun verifyChain(chain: List<X509Certificate>): Pair<Boolean, String> {
        if (chain.isEmpty()) return false to "цепочка пуста"
        return try {
            checkTrusted(chain)
            true to "публично доверенный CA"
        } catch (e: Throwable) {
            false to (e.message?.lineSequence()?.firstOrNull()?.take(120) ?: e::class.java.simpleName)
        }
    }

    /**
     * Проверка цепочки штатным X509TrustManager: он, в отличие от ручного PKIX-валидатора,
     * достраивает кросс-подписанные цепочки (например, GTS Root R4, подписанный GlobalSign).
     */
    private fun checkTrusted(chain: List<X509Certificate>) {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val tm = tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: throw CertificateException("нет X509TrustManager")
        val path = chain.toTypedArray()
        var last: Exception? = null
        for (authType in listOf("ECDHE_ECDSA", "ECDHE_RSA", "RSA", "UNKNOWN")) {
            try {
                tm.checkServerTrusted(path, authType)
                return
            } catch (e: Exception) {
                if (e.message?.contains("Unknown authType") == false) throw e
                last = e
            }
        }
        throw last ?: CertificateException("цепочка не принята")
    }
}
