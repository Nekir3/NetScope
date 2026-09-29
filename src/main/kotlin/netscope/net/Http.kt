package netscope.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.Locale
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

data class HttpReply(
    val url: String,
    val status: Int = 0,
    val statusLine: String = "",
    val headers: Map<String, String> = emptyMap(),
    val body: ByteArray = ByteArray(0),
    val ms: Long = 0,
    val bytes: Int = 0,
    val bodyMs: Long = 0,
    val server: String = "",
    val via: String = "",
    val location: String = "",
    val encoding: String = "",
    val error: String = "",
    val netError: NetError = NetError.NONE
) {
    val ok: Boolean get() = status in 200..399
    val text: String get() = String(body, Charsets.UTF_8)
    fun header(name: String): String = headers.entries.firstOrNull { it.key.equals(name, true) }?.value ?: ""
    fun hasHeader(name: String) = headers.keys.any { it.equals(name, true) }
}

object Http {
    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    val defaultUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"

    suspend fun get(
        url: String,
        timeoutMs: Int = 5000,
        headers: Map<String, String> = emptyMap(),
        maxBody: Int = 262144,
        connectTo: String? = null,
        sni: String? = null,
        method: String = "GET"
    ): HttpReply {
        val u = parse(url) ?: return HttpReply(url, error = "некорректный URL", netError = NetError.UNKNOWN)
        return request(u.scheme, u.host, u.path, u.port, timeoutMs, headers, maxBody, connectTo, sni, method)
    }

    suspend fun request(
        scheme: String,
        host: String,
        path: String = "/",
        port: Int = if (scheme == "https") 443 else 80,
        timeoutMs: Int = 5000,
        headers: Map<String, String> = emptyMap(),
        maxBody: Int = 262144,
        connectTo: String? = null,
        sni: String? = null,
        method: String = "GET",
        body: ByteArray? = null,
        contentType: String? = null
    ): HttpReply = withContext(Dispatchers.IO) {
        val t0 = nanoMs()
        var raw: Socket? = null
        var ssl: SSLSocket? = null
        val target = connectTo ?: host
        val full = "$scheme://$host$path"
        try {
            if (scheme == "https") {
                val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), SecureRandom()) }
                val s = ctx.socketFactory.createSocket() as SSLSocket
                ssl = s
                val p = s.sslParameters
                p.applicationProtocols = arrayOf("http/1.1")
                runCatching { p.serverNames = listOf(SNIHostName(sni ?: host)) }
                p.endpointIdentificationAlgorithm = null
                s.sslParameters = p
                s.connect(InetSocketAddress(target, port), timeoutMs)
                s.soTimeout = timeoutMs
                s.startHandshake()
                raw = s
            } else {
                val s = Socket()
                s.tcpNoDelay = true
                s.connect(InetSocketAddress(target, port), timeoutMs)
                s.soTimeout = timeoutMs
                raw = s
            }
            val out = raw!!.getOutputStream()
            val req = StringBuilder()
            req.append(method).append(' ').append(path.ifEmpty { "/" }).append(" HTTP/1.1\r\n")
            req.append("Host: ").append(host).append(if (port == 80 || port == 443) "" else ":$port").append("\r\n")
            req.append("User-Agent: ").append(headers["User-Agent"] ?: defaultUa).append("\r\n")
            req.append("Accept: */*\r\n")
            req.append("Accept-Encoding: identity\r\n")
            req.append("Connection: close\r\n")
            if (contentType != null) req.append("Content-Type: ").append(contentType).append("\r\n")
            if (body != null) req.append("Content-Length: ").append(body.size).append("\r\n")
            for ((k, v) in headers) {
                if (k.equals("User-Agent", true) || k.equals("Host", true)) continue
                req.append(k).append(": ").append(v).append("\r\n")
            }
            req.append("\r\n")
            out.write(req.toString().toByteArray(Charsets.ISO_8859_1))
            if (body != null) out.write(body)
            out.flush()

            val input = raw!!.getInputStream()
            val statusLine = readLine(input) ?: return@withContext HttpReply(full, error = "пустой ответ", ms = nanoMs() - t0, netError = NetError.EOF)
            val status = Regex("HTTP/\\d\\.\\d\\s+(\\d{3})").find(statusLine)?.groupValues?.get(1)?.toIntOrNull() ?: 0
            val hdrs = LinkedHashMap<String, String>()
            while (true) {
                val l = readLine(input) ?: break
                if (l.isEmpty()) break
                val i = l.indexOf(':')
                if (i <= 0) continue
                hdrs[l.substring(0, i).trim()] = l.substring(i + 1).trim()
            }
            val encoding = hdrs.entries.firstOrNull { it.key.equals("Transfer-Encoding", true) }?.value?.lowercase(Locale.ROOT) ?: ""
            val tBody = nanoMs()
            val payload = when {
                encoding.contains("chunked") -> readChunked(input, maxBody)
                hdrs.entries.any { it.key.equals("Content-Length", true) } -> {
                    val len = hdrs.entries.first { it.key.equals("Content-Length", true) }.value.toIntOrNull() ?: 0
                    readFully(input, minOf(len, maxBody))
                }
                else -> readUntilEof(input, maxBody)
            }
            val bodyMs = nanoMs() - tBody
            HttpReply(
                url = full, status = status, statusLine = statusLine, headers = hdrs, body = payload,
                ms = nanoMs() - t0, bytes = payload.size, bodyMs = bodyMs,
                server = hdrs.entries.firstOrNull { it.key.equals("Server", true) }?.value ?: "",
                via = hdrs.entries.firstOrNull { it.key.equals("Via", true) }?.value ?: "",
                location = hdrs.entries.firstOrNull { it.key.equals("Location", true) }?.value ?: "",
                encoding = encoding
            )
        } catch (e: Throwable) {
            HttpReply(full, error = e.message ?: e::class.java.simpleName, ms = nanoMs() - t0, netError = classify(e))
        } finally {
            runCatching { ssl?.close() ?: raw?.close() }
        }
    }

    private fun readLine(inp: InputStream): String? {
        val buf = ByteArrayOutputStream(256)
        while (true) {
            val c = inp.read()
            if (c < 0) return if (buf.size() == 0) null else buf.toString(Charsets.ISO_8859_1.name())
            if (c == '\n'.code) break
            if (c != '\r'.code) buf.write(c)
            if (buf.size() > 8192) break
        }
        return buf.toString(Charsets.ISO_8859_1.name())
    }

    private fun readFully(inp: InputStream, n: Int): ByteArray {
        val out = ByteArrayOutputStream(n.coerceAtMost(1 shl 20))
        val buf = ByteArray(16384)
        var left = n
        while (left > 0) {
            val r = inp.read(buf, 0, minOf(buf.size, left))
            if (r < 0) break
            out.write(buf, 0, r)
            left -= r
        }
        return out.toByteArray()
    }

    private fun readUntilEof(inp: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(16384)
        while (out.size() < max) {
            val r = inp.read(buf, 0, minOf(buf.size, max - out.size()))
            if (r < 0) break
            out.write(buf, 0, r)
        }
        return out.toByteArray()
    }

    private fun readChunked(inp: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream()
        while (true) {
            val sizeLine = readLine(inp) ?: break
            val size = sizeLine.substringBefore(';').trim().toIntOrNull(16) ?: break
            if (size == 0) break
            out.write(readFully(inp, size))
            readLine(inp)
            if (out.size() > max) break
        }
        return out.toByteArray()
    }

    data class Url(val scheme: String, val host: String, val port: Int, val path: String)

    fun parse(url: String): Url? {
        val m = Regex("^(https?)://([^/:?#]+)(?::(\\d+))?([^#]*)").find(url.trim()) ?: return null
        val scheme = m.groupValues[1].lowercase(Locale.ROOT)
        val host = m.groupValues[2]
        val port = m.groupValues[3].ifEmpty { if (scheme == "https") "443" else "80" }.toIntOrNull() ?: return null
        val path = m.groupValues[4].ifEmpty { "/" }
        return Url(scheme, host, port, path)
    }
}
