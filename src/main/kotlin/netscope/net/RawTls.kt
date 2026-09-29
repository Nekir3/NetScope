package netscope.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

private class Buf {
    private val b = ByteArrayOutputStream(1024)
    fun u8(v: Int) { b.write(v and 0xFF) }
    fun u16(v: Int) { u8(v shr 8); u8(v) }
    fun u24(v: Int) { u8(v shr 16); u8(v shr 8); u8(v) }
    fun raw(a: ByteArray) { b.write(a, 0, a.size) }
    fun raw(a: ByteArray, off: Int, len: Int) { b.write(a, off, len) }
    val size: Int get() = b.size()
    fun bytes(): ByteArray = b.toByteArray()
}

fun tlsVersionName(v: Int): String = when (v) {
    0x0300 -> "SSL 3.0"; 0x0301 -> "TLS 1.0"; 0x0302 -> "TLS 1.1"
    0x0303 -> "TLS 1.2"; 0x0304 -> "TLS 1.3"; else -> "0x%04x".format(v)
}

fun alertName(code: Int): String = when (code) {
    0 -> "close_notify"; 10 -> "unexpected_message"; 20 -> "bad_record_mac"; 21 -> "decryption_failed"
    22 -> "record_overflow"; 40 -> "handshake_failure"; 42 -> "bad_certificate"
    43 -> "unsupported_certificate"; 44 -> "certificate_revoked"; 45 -> "certificate_expired"
    46 -> "certificate_unknown"; 47 -> "illegal_parameter"; 48 -> "unknown_ca"
    49 -> "access_denied"; 50 -> "decode_error"; 51 -> "decrypt_error"; 70 -> "protocol_version"
    71 -> "insufficient_security"; 80 -> "internal_error"; 86 -> "inappropriate_fallback"
    90 -> "user_canceled"; 109 -> "missing_extension"; 112 -> "unrecognized_name"
    120 -> "no_application_protocol"; else -> "alert_$code"
}

private fun alertLevelName(v: Int) = if (v == 1) "warning" else if (v == 2) "fatal" else "info"

/**
 * Спецификация ClientHello со всеми хитрыми вариантами, которые нужны для проверки,
 * как именно middlebox инспектирует рукопожатие.
 */
data class HelloSpec(
    val sni: String? = null,
    val sniBytes: ByteArray? = null,
    val sniExtensionId: Int = 0x0000,
    val versions: List<Int> = listOf(0x0304, 0x0303, 0x0302),
    val alpn: List<String> = listOf("h2", "http/1.1"),
    val grease: Boolean = true,
    val padBeforeSni: Int = 0,
    val padTail: Int = 0,
    val firstRecordBytes: Int = 0,
    val recordVersion: Int = 0x0301,
    val sessionIdLen: Int = 32,
    val extraUnknownExt: Boolean = true,
    val label: String = "обычный ClientHello"
) {
    fun describe(): String = label
}

object TlsWire {
    private val rnd = SecureRandom()
    private val GREASE_VALUES = intArrayOf(0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a)
    private const val GREASE_EXT = 0x0a0a

    private val CIPHERS = intArrayOf(
        0x1301, 0x1302, 0x1303,
        0xC02B, 0xC02F, 0xC02C, 0xC030, 0xC02F,
        0x009E, 0x009C, 0x003C, 0x003D, 0x002F, 0x0035, 0x000A, 0x0005
    )

    private fun grease() = GREASE_VALUES[rnd.nextInt(GREASE_VALUES.size)]

    private fun nameBytes(s: String): ByteArray = s.toByteArray(Charsets.US_ASCII)

    /** Собирает полный TLS-поток (один или несколько record'ов) для отправки. */
    fun build(spec: HelloSpec): ByteArray {
        val ext = Buf()
        val order = ArrayList<Pair<Int, ByteArray>>()

        val sniPayload: ByteArray? = spec.sniBytes ?: spec.sni?.let { nameBytes(it) }
        if (sniPayload != null && spec.sniExtensionId != -1) {
            val inner = Buf()
            inner.u16(1)          // тип: host_name
            inner.u16(sniPayload.size)
            inner.raw(sniPayload)
            val b = Buf()
            b.u16(inner.size)
            b.raw(inner.bytes())
            order.add(spec.sniExtensionId to b.bytes())
        }

        // supported_groups
        run {
            val b = Buf(); val g = Buf()
            g.u16(0x001d); g.u16(0x0017); g.u16(0x0018)
            b.u16(g.size); b.raw(g.bytes()); order.add(0x000a to b.bytes())
        }
        // ec_point_formats
        run {
            val b = Buf(); b.u8(1); b.u8(0); order.add(0x000b to b.bytes())
        }
        // ALPN
        if (spec.alpn.isNotEmpty()) {
            val inner = Buf()
            spec.alpn.forEach { inner.u8(it.length); inner.raw(nameBytes(it)) }
            val b = Buf(); b.u16(inner.size); b.raw(inner.bytes())
            order.add(0x0010 to b.bytes())
        }
        // signature_algorithms
        run {
            val inner = Buf()
            listOf(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201, 0x0203)
                .forEach { inner.u16(it) }
            val b = Buf(); b.u16(inner.size); b.raw(inner.bytes()); order.add(0x000d to b.bytes())
        }
        // supported_versions
        run {
            val inner = Buf()
            inner.u8(spec.versions.size * 2)
            spec.versions.forEach { inner.u16(it) }
            val b = Buf(); b.u16(inner.size); b.raw(inner.bytes()); order.add(0x002b to b.bytes())
        }
        // psk_key_exchange_modes
        run {
            val inner = Buf(); inner.u8(1); inner.u8(1)
            val b = Buf(); b.u16(inner.size); b.raw(inner.bytes()); order.add(0x002d to b.bytes())
        }
        // key_share x25519
        run {
            val key = ByteArray(32).also { rnd.nextBytes(it) }
            val entry = Buf(); entry.u16(0x001d); entry.u16(key.size); entry.raw(key)
            val inner = Buf(); inner.u16(entry.size); entry.bytes().let { inner.raw(it) }
            val b = Buf(); b.u16(inner.size); b.raw(inner.bytes()); order.add(0x0033 to b.bytes())
        }
        // session_ticket (empty)
        order.add(0x0023 to ByteArray(0))
        // renegotiation_info
        order.add(0xff01 to ByteArray(1))

        if (spec.extraUnknownExt) order.add(0x0016 to ByteArray(0))

        if (spec.grease) {
            val g = grease()
            order.add(0 to bunge(g, byteArrayOf()))
        }

        // «подушка» перед SNI: часть DPI смотрит только начало ClientHello
        val sniIndex = order.indexOfFirst { it.first == spec.sniExtensionId || (spec.sniExtensionId == 0 && it.first == 0) }
        if (spec.padBeforeSni > 0 && sniIndex > 0) {
            val pad = ByteArray(spec.padBeforeSni.coerceAtMost(250))
            rnd.nextBytes(pad)
            order.add(0x0015 to pad)
        }
        if (spec.padTail > 0) {
            order.add(0x0015 to ByteArray(spec.padTail.coerceAtMost(260)))
        }

        val extBuf = Buf()
        for ((id, data) in order) {
            if (spec.grease && id == 0) { extBuf.u16(grease()); extBuf.u16(data.size) } else extBuf.u16(id)
            extBuf.u16(data.size)
            extBuf.raw(data)
        }

        val body = Buf()
        body.u16(0x0303)
        val greeting = ByteArray(32).also { rnd.nextBytes(it) }
        body.raw(greeting)
        body.u8(spec.sessionIdLen)
        body.raw(ByteArray(spec.sessionIdLen).also { rnd.nextBytes(it) })

        val cs = Buf()
        if (spec.grease) cs.u16(grease())
        CIPHERS.forEach { cs.u16(it) }
        if (spec.grease) cs.u16(grease())
        body.u16(cs.size)
        body.raw(cs.bytes())

        body.u8(1); body.u8(0)

        body.u16(extBuf.size)
        body.raw(extBuf.bytes())

        val hs = Buf()
        hs.u8(0x01)
        hs.u24(body.size)
        hs.raw(body.bytes())
        val handshake = hs.bytes()

        if (spec.firstRecordBytes in 1 until handshake.size - 5) {
            val cut = spec.firstRecordBytes
            val out = Buf()
            // первый record: заголовок handshake обрезан
            out.u8(0x16); out.u16(spec.recordVersion); out.u16(cut)
            out.raw(handshake, 0, cut)
            val rest = handshake.size - cut
            val maxPayload = 16384
            var off = cut
            while (off < handshake.size) {
                val len = minOf(maxPayload, handshake.size - off)
                out.u8(0x16); out.u16(spec.recordVersion); out.u16(len)
                out.raw(handshake, off, len)
                off += len
            }
            return out.bytes()
        }
        val rec = Buf()
        rec.u8(0x16); rec.u16(spec.recordVersion); rec.u16(handshake.size)
        rec.raw(handshake)
        return rec.bytes()
    }

    private fun bunge(id: Int, data: ByteArray): ByteArray {
        val b = Buf()
        b.u16(id); b.u16(data.size); b.raw(data)
        return b.bytes()
    }

    fun randomId(): Int = rnd.nextInt(1, 0x7FFFFFFF)
}

enum class TlsState {
    HANDSHAKE_COMPLETE,   // дошли до ServerHello (+ сертификаты, если TLS<=1.2)
    SERVER_HELLO,         // сервер ответил, дальше шифровано (норма для TLS 1.3)
    ALERT,                // сервер прислал alert
    RST,                  // TCP RST — типичная картина DPI-инъекции
    TIMEOUT,              // тишина в эфире — чёрная дыра
    EOF,                  // сервер закрыл соединение
    CONNECT_FAILED,
    PROTOCOL_ERROR
}

data class TlsReply(
    val state: TlsState,
    val msFirstByte: Long = 0,
    val msDone: Long = 0,
    val negotiated: String? = null,
    val legacyVersion: String? = null,
    val cipherSuite: String? = null,
    val alpn: String? = null,
    val alerts: List<String> = emptyList(),
    val certs: List<X509Certificate> = emptyList(),
    val handshakeTypes: List<Int> = emptyList(),
    val netError: NetError = NetError.NONE,
    val message: String = ""
) {
    val hasRst: Boolean get() = state == TlsState.RST
    val silent: Boolean get() = state == TlsState.TIMEOUT
    val blocked: Boolean get() = state == TlsState.RST || state == TlsState.TIMEOUT || state == TlsState.EOF
    val certChain: List<X509Certificate> get() = certs
}

object TlsProbeRaw {
    private fun parseCerts(data: ByteArray): List<X509Certificate> {
        return try {
            var p = 0
            fun u24(at: Int) = ((data[at].toInt() and 0xFF) shl 16) or ((data[at + 1].toInt() and 0xFF) shl 8) or (data[at + 2].toInt() and 0xFF)
            val listLen = u24(0); p = 3
            val cf = CertificateFactory.getInstance("X.509")
            val out = ArrayList<X509Certificate>()
            while (p + 3 <= data.size && p + 3 <= 3 + listLen) {
                val len = u24(p); p += 3
                if (p + len > data.size) break
                val der = data.copyOfRange(p, p + len)
                out.add(cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate)
                p += len
            }
            out
        } catch (_: Throwable) { emptyList() }
    }

    private fun parseExtensions(data: ByteArray, from: Int): Pair<Map<Int, ByteArray>, Int> {
        val m = HashMap<Int, ByteArray>()
        var p = from
        if (p + 2 > data.size) return m to p
        val total = ((data[p].toInt() and 0xFF) shl 8) or (data[p + 1].toInt() and 0xFF)
        p += 2
        val end = minOf(data.size, p + total)
        while (p + 4 <= end) {
            val id = ((data[p].toInt() and 0xFF) shl 8) or (data[p + 1].toInt() and 0xFF)
            val len = ((data[p + 2].toInt() and 0xFF) shl 8) or (data[p + 3].toInt() and 0xFF)
            p += 4
            if (p + len > end) break
            m[id] = data.copyOfRange(p, p + len)
            p += len
        }
        return m to p
    }

    private fun u16(d: ByteArray, p: Int) = ((d[p].toInt() and 0xFF) shl 8) or (d[p + 1].toInt() and 0xFF)

    private data class Hello(
        val legacy: String,
        val negotiated: String?,
        val cipher: String?,
        val alpn: String?
    )

    private fun parseServerHello(hb: ByteArray): Hello {
        if (hb.size < 2) return Hello("?", null, null, null)
        val legacy = tlsVersionName(u16(hb, 0))
        var r = 2 + 32
        if (r >= hb.size) return Hello(legacy, null, null, null)
        val sidLen = hb[r].toInt() and 0xFF
        r += 1 + sidLen
        if (r + 3 > hb.size) return Hello(legacy, null, null, null)
        val cipher = "0x%04x".format(u16(hb, r))
        r += 3
        if (r > hb.size) return Hello(legacy, null, cipher, null)
        val exts = parseExtensions(hb, r).first

        var negotiated: String? = null
        val sv = exts[0x002b]
        if (sv != null && sv.size >= 2) {
            negotiated = tlsVersionName(if (sv.size >= 3) u16(sv, 1) else u16(sv, 0))
        }
        var alpn: String? = null
        val a = exts[0x0010]
        if (a != null) {
            var k = 1
            if (k < a.size) {
                val l = a[k].toInt() and 0xFF
                if (k + 1 + l <= a.size) alpn = String(a, k + 1, l, Charsets.US_ASCII)
            }
        }
        return Hello(legacy, negotiated, cipher, alpn)
    }

    /**
     * Отправляет [payload] на [host]:[port] и разбирает TLS-ответ до первого
     * терминального состояния. Ключевое — точные тайминги: RST, пришедший заметно
     * раньше половины RTT, почти наверняка сгенерирован middlebox'ом, а не сервером.
     */
    suspend fun exchange(
        host: String, port: Int = 443, payload: ByteArray,
        connectTimeoutMs: Int = 3000, readTimeoutMs: Int = 2500,
        splitWrites: List<Int> = emptyList(), gapMs: Long = 0
    ): TlsReply = withContext(Dispatchers.IO) {
        val wire = try { Wire.open(host, port, connectTimeoutMs) } catch (e: Throwable) {
            return@withContext TlsReply(TlsState.CONNECT_FAILED, netError = classify(e), message = e.message ?: "")
        }
        val t0 = nanoMs()
        try {
            if (splitWrites.isEmpty()) wire.write(payload) else {
                var off = 0
                for (cut in splitWrites) {
                    if (cut <= off || cut > payload.size) continue
                    wire.write(payload, off, cut - off)
                    off = cut
                    if (gapMs > 0) Thread.sleep(gapMs)
                }
                if (off < payload.size) wire.write(payload, off, payload.size - off)
            }
            val tSent = nanoMs()
            val buf = ByteArray(16384)
            var msFirst = -1L
            var state = TlsState.PROTOCOL_ERROR
            var negotiated: String? = null
            var legacy: String? = null
            var cipher: String? = null
            var alpn: String? = null
            val alerts = ArrayList<String>()
            var certs: List<X509Certificate> = emptyList()
            val types = ArrayList<Int>()
            var sawServerHello = false
            var sawFinished = false

            outer@ while (true) {
                val left = (readTimeoutMs - (nanoMs() - tSent)).toInt()
                if (left <= 0) { if (state != TlsState.TIMEOUT) state = TlsState.TIMEOUT; break@outer }
                val n = try { wire.read(buf, left) } catch (e: Throwable) {
                    val err = classify(e)
                    state = if (err == NetError.RESET || err == NetError.REFUSED) TlsState.RST else TlsState.PROTOCOL_ERROR
                    break@outer
                }
                if (n < 0) { state = TlsState.EOF; break@outer }
                if (msFirst < 0) msFirst = nanoMs() - tSent
                var p = 0
                while (p + 5 <= n) {
                    val type = buf[p].toInt() and 0xFF
                    val len = ((buf[p + 3].toInt() and 0xFF) shl 8) or (buf[p + 4].toInt() and 0xFF)
                    if (p + 5 + len > n) break
                    val body = buf.copyOfRange(p + 5, p + 5 + len)
                    when (type) {
                        0x16 -> {
                            var q = 0
                            while (q + 4 <= body.size) {
                                val ht = body[q].toInt() and 0xFF
                                val hl = ((body[q + 1].toInt() and 0xFF) shl 16) or ((body[q + 2].toInt() and 0xFF) shl 8) or (body[q + 3].toInt() and 0xFF)
                                if (q + 4 + hl > body.size) break
                                types.add(ht)
                                val hb = body.copyOfRange(q + 4, q + 4 + hl)
                                when (ht) {
                                    0x02 -> {
                                        sawServerHello = true
                                        val h = parseServerHello(hb)
                                        legacy = h.legacy
                                        negotiated = h.negotiated
                                        cipher = h.cipher
                                        alpn = h.alpn
                                    }
                                    0x0E -> if (certs.isEmpty()) certs = parseCerts(hb)
                                    0x0C, 0x14, 0x0F -> sawFinished = true
                                }
                                q += 4 + hl
                            }
                        }
                        0x15 -> {
                            if (body.size >= 2) alerts.add("${alertLevelName(body[0].toInt() and 0xFF)}: ${alertName(body[1].toInt() and 0xFF)}")
                        }
                        0x14 -> { /* change_cipher_spec */ }
                        else -> { /* игнорируем */ }
                    }
                    p += 5 + len
                }
                val terminal = alerts.isNotEmpty() || (sawServerHello && (certs.isNotEmpty() || sawFinished))
                if (terminal) break@outer
            }
            val finalState = when {
                alerts.isNotEmpty() -> TlsState.ALERT
                sawFinished || (sawServerHello && certs.isNotEmpty()) -> TlsState.HANDSHAKE_COMPLETE
                sawServerHello -> TlsState.SERVER_HELLO
                state == TlsState.RST -> TlsState.RST
                state == TlsState.EOF -> TlsState.EOF
                state == TlsState.TIMEOUT -> TlsState.TIMEOUT
                else -> TlsState.PROTOCOL_ERROR
            }
            TlsReply(
                state = finalState,
                msFirstByte = if (msFirst < 0) nanoMs() - tSent else msFirst,
                msDone = nanoMs() - t0,
                negotiated = negotiated ?: legacy,
                legacyVersion = legacy,
                cipherSuite = cipher,
                alpn = alpn,
                alerts = alerts,
                certs = certs,
                handshakeTypes = types
            )
        } finally {
            runCatching { wire.close() }
        }
    }

    fun exchangeBlocking(host: String, port: Int = 443, payload: ByteArray, connectTimeoutMs: Int = 3000, readTimeoutMs: Int = 2500): TlsReply =
        kotlinx.coroutines.runBlocking { exchange(host, port, payload, connectTimeoutMs, readTimeoutMs) }
}
