package netscope.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom

/**
 * DNS-over-HTTPS. Нужен как эталон: любой ответ системного резолвера,
 * не совпадающий с DoH, — это вмешательство в DNS.
 */
data class DohServer(val name: String, val host: String, val path: String = "/dns-query", val ipv4: String? = null) {
    val url: String get() = "https://$host$path"
}

object Doh {
    val default = listOf(
        DohServer("Cloudflare", "cloudflare-dns.com", ipv4 = "1.1.1.1"),
        DohServer("Google", "dns.google", path = "/dns-query", ipv4 = "8.8.8.8"),
        DohServer("Quad9", "dns.quad9.net", path = "/dns-query", ipv4 = "9.9.9.9"),
        DohServer("AdGuard", "dns.adguard-dns.com", ipv4 = "94.140.14.14"),
        DohServer("CleanBrowsing", "doh.cleanbrowsing.org", path = "/security-filter", ipv4 = "185.228.168.9")
    )

    suspend fun query(
        server: DohServer, name: String, type: Int = DnsType.A,
        timeoutMs: Int = 4000, forceIp: Boolean = true
    ): DnsResponse = withContext(Dispatchers.IO) {
        val q = Dns.buildQuery(name, type)
        val rep = Http.request(
            scheme = "https",
            host = server.host,
            path = server.path + "?dns=" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(q),
            port = 443,
            timeoutMs = timeoutMs,
            connectTo = if (forceIp) server.ipv4 else null,
            sni = server.host,
            headers = mapOf("Accept" to "application/dns-message")
        )
        if (rep.netError != NetError.NONE || rep.status !in 200..299) {
            throw IllegalStateException("DoH ${server.name}: ${rep.error.ifBlank { "HTTP ${rep.status}" }}")
        }
        Dns.parse(rep.body, name, type)
    }

    fun queryJson(server: DohServer, name: String, type: Int = DnsType.A, timeoutMs: Int = 4000, forceIp: Boolean = true): String =
        kotlinx.coroutines.runBlocking {
            val t = if (type == DnsType.TXT) "TXT" else if (type == DnsType.AAAA) "AAAA" else "A"
            val rep = Http.request(
                scheme = "https",
                host = server.host,
                path = "/dns-query?name=$name&type=$t",
                port = 443,
                timeoutMs = timeoutMs,
                headers = mapOf("Accept" to "application/dns-json"),
                connectTo = if (forceIp) server.ipv4 else null,
                sni = server.host
            )
            rep.text
        }
}

/** Минимальный STUN Binding Request: показывает, какой адрес видит WebRTC-пир. */
object Stun {
    private val MAGIC = 0x2112A442L
    private val rnd = SecureRandom()

    data class Result(val ok: Boolean, val mappedAddress: String = "", val ms: Long = 0, val error: String = "", val type: String = "")

    data class Server(val name: String, val host: String, val port: Int)

    val google = Server("Google STUN", "stun.l.google.com", 19302)
    val cloudflare = Server("Cloudflare", "stun.cloudflare.com", 3478)
    val nextcloud = Server("Nextcloud", "stun.nextcloud.com", 443)
    val stunProtocol = Server("stunprotocol.org", "stun.stunprotocol.org", 3478)

    fun binding(server: Server, timeoutMs: Int = 2500, bindAddr: java.net.InetSocketAddress? = null): Result {
        val t0 = nanoMs()
        var sock: DatagramSocket? = null
        return try {
            val id = ByteArray(12).also { rnd.nextBytes(it) }
            val msg = ByteArray(20)
            msg[0] = 0x00; msg[1] = 0x01
            msg[2] = 0x00; msg[3] = 0x00
            writeInt(msg, 4, MAGIC)
            System.arraycopy(id, 0, msg, 8, 12)
            sock = DatagramSocket()
            bindAddr?.let { runCatching { sock!!.bind(it) } }
            sock!!.soTimeout = timeoutMs
            val host = runCatching { InetAddress.getByName(server.host) }.getOrElse { return Result(false, error = "DNS: ${it.message}", ms = nanoMs() - t0) }
            sock!!.send(DatagramPacket(msg, msg.size, host, server.port))
            val buf = ByteArray(1024)
            val pkt = DatagramPacket(buf, buf.size)
            sock!!.receive(pkt)
            val ms = nanoMs() - t0
            parse(buf.copyOf(pkt.length), ms)
        } catch (e: Throwable) {
            Result(false, ms = nanoMs() - t0, error = if (e is SocketTimeoutException) "таймаут" else (e.message ?: e::class.java.simpleName))
        } finally {
            runCatching { sock?.close() }
        }
    }

    private fun writeInt(a: ByteArray, p: Int, v: Long) {
        a[p] = (v shr 24).toByte(); a[p + 1] = (v shr 16).toByte(); a[p + 2] = (v shr 8).toByte(); a[p + 3] = v.toByte()
    }

    private fun parse(msg: ByteArray, ms: Long): Result {
        if (msg.size < 20) return Result(false, ms = ms, error = "короткий ответ")
        val type = ((msg[0].toInt() and 0xFF) shl 8) or (msg[1].toInt() and 0xFF)
        val len = ((msg[2].toInt() and 0xFF) shl 8) or (msg[3].toInt() and 0xFF)
        var p = 20
        val end = minOf(msg.size, 20 + len)
        while (p + 4 <= end) {
            val at = ((msg[p].toInt() and 0xFF) shl 8) or (msg[p + 1].toInt() and 0xFF)
            val al = ((msg[p + 2].toInt() and 0xFF) shl 8) or (msg[p + 3].toInt() and 0xFF)
            p += 4
            if (p + al > msg.size) break
            val v = msg.copyOfRange(p, p + al)
            when (at) {
                0x0020, 0x0001 -> {
                    if (v.size >= 8) {
                        val family = v[1].toInt() and 0xFF
                        val addr = if (family == 0x01) {
                            val a = ((((v[2].toInt() and 0xFF) xor 0x21) shl 24) or
                                    (((v[3].toInt() and 0xFF) xor 0x12) shl 16) or
                                    (((v[4].toInt() and 0xFF) xor 0xA4) shl 8) or
                                    ((v[5].toInt() and 0xFF) xor 0x42))
                            "${(a ushr 24) and 0xFF}.${(a ushr 16) and 0xFF}.${(a ushr 8) and 0xFF}.${a and 0xFF}"
                        } else Dns.formatIp(v.copyOfRange(4, minOf(20, v.size)))
                        return Result(true, addr, ms, type = "0x%04x".format(type))
                    }
                }
                0x8022 -> return Result(false, ms = ms, error = "alternate-server", type = "0x%04x".format(type))
                0x0101 -> return Result(false, ms = ms, error = "error-response", type = "0x%04x".format(type))
            }
            p += al
            if ((al and 3) != 0) p += 4 - (al and 3)
        }
        return Result(false, ms = ms, error = "нет MAPPED-ADDRESS", type = "0x%04x".format(type))
    }
}
