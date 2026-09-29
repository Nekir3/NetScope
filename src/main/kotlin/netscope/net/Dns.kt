package netscope.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ThreadLocalRandom

object DnsType {
    const val A = 1
    const val NS = 2
    const val CNAME = 5
    const val SOA = 6
    const val PTR = 12
    const val MX = 15
    const val TXT = 16
    const val AAAA = 28
    const val SRV = 33
    const val HTTPS = 65
    const val ANY = 255
    const val T = 255
    fun name(t: Int) = when (t) {
        A -> "A"; AAAA -> "AAAA"; CNAME -> "CNAME"; NS -> "NS"; TXT -> "TXT"; MX -> "MX"
        SOA -> "SOA"; PTR -> "PTR"; SRV -> "SRV"; HTTPS -> "HTTPS/SVCB"; ANY -> "ANY"; else -> "TYPE$t"
    }
}

data class DnsRr(
    val name: String,
    val type: Int,
    val ttl: Long,
    val raw: ByteArray
) {
    val ipv4: String? get() = if (type == DnsType.A && raw.size == 4) formatIpString(raw) else null
    val ipv6: String? get() = if (type == DnsType.AAAA && raw.size == 16) formatIpString(raw) else null
    val address: String? get() = ipv4 ?: ipv6
    val cname: String? get() = if (type == DnsType.CNAME) readDnsName(raw, 0).first else null
    val ns: String? get() = if (type == DnsType.NS) readDnsName(raw, 0).first else null
    val txt: String?
        get() {
            if (type != DnsType.TXT) return null
            return try {
                var i = 0; val sb = StringBuilder()
                while (i < raw.size) {
                    val len = raw[i].toInt() and 0xFF
                    if (len > raw.size - i - 1) break
                    sb.append(String(raw, i + 1, len, Charsets.UTF_8))
                    i += 1 + len
                }
                sb.toString()
            } catch (_: Throwable) { null }
        }

    override fun equals(other: Any?) = other is DnsRr && other.type == type && other.raw.contentEquals(raw) && other.name == name
    override fun hashCode() = 31 * name.hashCode() + type * 17 + raw.contentHashCode()
}

data class DnsResponse(
    val id: Int,
    val flags: Int,
    val question: String,
    val qtype: Int,
    val answers: List<DnsRr>,
    val authorities: List<DnsRr>,
    val additionals: List<DnsRr>,
    val raw: ByteArray
) {
    val rcode: Int get() = flags and 0x0F
    val truncated: Boolean get() = flags and 0x0200 != 0
    val recursionAvailable: Boolean get() = flags and 0x0080 != 0
    val authentic: Boolean get() = flags and 0x0020 != 0
    val questionEcho: String by lazy { (answers.firstOrNull { it.type == qtype }?.name) ?: question }

    val addresses: List<String> get() = answers.mapNotNull { it.address }.distinct()
    val v4: List<String> get() = answers.mapNotNull { it.ipv4 }.distinct()
    val v6: List<String> get() = answers.mapNotNull { it.ipv6 }.distinct()
    val cnames: List<String> get() = answers.mapNotNull { it.cname }.distinct()
    val txts: List<String> get() = answers.mapNotNull { it.txt }.filter { it.isNotBlank() }
    val nsNames: List<String> get() = answers.mapNotNull { it.ns }.distinct()

    fun statusText(): String = when {
        addresses.isNotEmpty() -> addresses.joinToString(", ")
        cnames.isNotEmpty() -> "CNAME " + cnames.joinToString(", ")
        txts.isNotEmpty() -> "TXT " + txts.joinToString(" | ").take(80)
        rcode == 3 -> "NXDOMAIN"
        rcode == 0 -> "пусто (NODATA)"
        else -> "rcode=$rcode"
    }
}

class DnsException(message: String) : Exception(message)

object Dns {
    private fun randomId() = ThreadLocalRandom.current().nextInt(1, 0xFFFF)

    fun buildQuery(name: String, type: Int, id: Int = randomId(), recursionDesired: Boolean = true, ednsUdpSize: Int = 0, dnssec: Boolean = false): ByteArray {
        val out = ByteArrayOutputStream(512)
        out.write(id shr 8 and 0xFF); out.write(id and 0xFF)
        val flags = if (recursionDesired) 0x0100 else 0x0000
        out.write(flags shr 8 and 0xFF); out.write(flags and 0xFF)
        out.write(0); out.write(1)      // QDCOUNT
        out.write(0); out.write(0)
        out.write(0); out.write(0)
        out.write(0); out.write(if (ednsUdpSize > 0) 1 else 0)
        out.write(0); out.write(0)
        writeName(out, name)
        out.write(type shr 8 and 0xFF); out.write(type and 0xFF)
        out.write(0); out.write(1)       // IN
        if (ednsUdpSize > 0) {
            out.write(0)                 // root name
            out.write(0); out.write(41)  // OPT
            out.write(ednsUdpSize shr 8 and 0xFF); out.write(ednsUdpSize and 0xFF)
            val ttl = if (dnssec) 0x8000 else 0
            out.write(ttl shr 24 and 0xFF); out.write(ttl shr 16 and 0xFF); out.write(ttl shr 8 and 0xFF); out.write(ttl and 0xFF)
            out.write(0); out.write(0)
        }
        return out.toByteArray()
    }

    private fun writeName(out: ByteArrayOutputStream, name: String) {
        val trimmed = name.trim('.')
        if (trimmed.isNotEmpty()) {
            for (label in trimmed.split('.')) {
                val bytes = label.toByteArray(Charsets.UTF_8)
                val len = bytes.size.coerceAtMost(63)
                out.write(len)
                out.write(bytes, 0, len)
            }
        }
        out.write(0)
    }

    fun parse(msg: ByteArray, expectedName: String = "", expectedType: Int = 0): DnsResponse {
        fun u16(p: Int) = ((msg[p].toInt() and 0xFF) shl 8) or (msg[p + 1].toInt() and 0xFF)
        fun u32(p: Int) = ((msg[p].toLong() and 0xFF) shl 24) or ((msg[p + 1].toLong() and 0xFF) shl 16) or
                ((msg[p + 2].toLong() and 0xFF) shl 8) or (msg[p + 3].toLong() and 0xFF)

        if (msg.size < 12) throw DnsException("короткий ответ (${msg.size} байт)")
        val id = u16(0); val flags = u16(2)
        val qd = u16(4); val an = u16(6); val ns = u16(8); val ar = u16(10)
        var p = 12
        var qname = ""
        var qtype = 0
        if (qd > 0) {
            val rn = readName(msg, p); qname = rn.first; p = rn.second
            qtype = u16(p); p += 4
        }
        fun section(count: Int): List<DnsRr> {
            val list = ArrayList<DnsRr>(count)
            repeat(count) {
                if (p + 10 > msg.size) return list
                val nm = readName(msg, p); p = nm.second
                if (p + 10 > msg.size) return list
                val t = u16(p); val ttl = u32(p + 4); val rdlen = u16(p + 8)
                p += 10
                if (p + rdlen > msg.size) return list
                list.add(DnsRr(nm.first, t, ttl, msg.copyOfRange(p, p + rdlen)))
                p += rdlen
            }
            return list
        }
        val answers = section(an)
        val authorities = section(ns)
        val additionals = section(ar)
        return DnsResponse(id, flags, if (qname.isEmpty()) expectedName else qname, if (qtype == 0) expectedType else qtype, answers, authorities, additionals, msg)
    }

    fun readName(msg: ByteArray, start: Int): Pair<String, Int> = readDnsName(msg, start)

    /** UDP-запрос к произвольному резолверу. Порт по умолчанию 53, но можно указать любой. */
    suspend fun queryUdp(
        server: String, port: Int = 53, name: String, type: Int = DnsType.A,
        timeoutMs: Int = 2500, bindLocal: java.net.InetSocketAddress? = null,
        ednsUdpSize: Int = 0, dnssec: Boolean = false
    ): DnsResponse = withContext(Dispatchers.IO) {
        val id = randomId()
        val q = buildQuery(name, type, id, ednsUdpSize = ednsUdpSize, dnssec = dnssec)
        DatagramSocket().use { sock ->
            bindLocal?.let { try { sock.bind(it) } catch (_: Throwable) {} }
            sock.soTimeout = timeoutMs
            val addr = InetAddress.getByName(server)
            sock.send(DatagramPacket(q, q.size, addr, port))
            val buf = ByteArray(4096)
            val pkt = DatagramPacket(buf, buf.size)
            val t0 = System.currentTimeMillis()
            while (System.currentTimeMillis() - t0 < timeoutMs) {
                sock.receive(pkt)
                val resp = parse(buf.copyOf(pkt.length))
                if (resp.id == id) return@withContext resp
            }
            throw SocketTimeoutException("нет ответа от $server:$port")
        }
    }

    fun queryUdpBlocking(
        server: String, port: Int = 53, name: String, type: Int = DnsType.A,
        timeoutMs: Int = 2500, bindLocal: java.net.InetSocketAddress? = null
    ): DnsResponse {
        val id = randomId()
        val q = buildQuery(name, type, id)
        DatagramSocket().use { sock ->
            bindLocal?.let { try { sock.bind(it) } catch (_: Throwable) {} }
            sock.soTimeout = timeoutMs
            sock.send(DatagramPacket(q, q.size, InetAddress.getByName(server), port))
            val buf = ByteArray(4096)
            val pkt = DatagramPacket(buf, buf.size)
            val t0 = System.currentTimeMillis()
            while (System.currentTimeMillis() - t0 < timeoutMs) {
                sock.receive(pkt)
                val resp = parse(buf.copyOf(pkt.length))
                if (resp.id == id) return resp
            }
            throw SocketTimeoutException("нет ответа от $server:$port")
        }
    }

    fun formatIp(bytes: ByteArray): String = formatIpString(bytes)

    fun readNameTop(msg: ByteArray, start: Int): Pair<String, Int> = readDnsName(msg, start)
}

internal fun formatIpString(bytes: ByteArray): String {
    if (bytes.size == 4) return bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
    if (bytes.size == 16) {
        val sb = StringBuilder()
        for (i in 0 until 16 step 2) {
            if (i > 0) sb.append(':')
            sb.append(Integer.toHexString(((bytes[i].toInt() and 0xFF) shl 8) or (bytes[i + 1].toInt() and 0xFF)))
        }
        return sb.toString()
    }
    return bytes.joinToString("") { "%02x".format(it) }
}

internal fun readDnsName(msg: ByteArray, start: Int): Pair<String, Int> {
    val labels = ArrayList<String>()
    var p = start
    var jumped = false
    var end = start
    var guard = 0
    while (p < msg.size && guard++ < 128) {
        val len = msg[p].toInt() and 0xFF
        when {
            len == 0 -> { p++; if (!jumped) end = p; return labels.joinToString(".") to end }
            len and 0xC0 == 0xC0 -> {
                if (p + 1 >= msg.size) break
                val off = ((len and 0x3F) shl 8) or (msg[p + 1].toInt() and 0xFF)
                if (!jumped) end = p + 2
                jumped = true
                if (off >= msg.size) break
                p = off
            }
            else -> {
                if (p + 1 + len > msg.size) break
                labels.add(String(msg, p + 1, len, Charsets.UTF_8))
                p += 1 + len
                if (!jumped) end = p
            }
        }
    }
    return labels.joinToString(".") to end
}
