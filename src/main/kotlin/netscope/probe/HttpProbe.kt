package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Mode
import netscope.core.Targets
import netscope.core.Verdict
import netscope.net.Http
import netscope.net.HttpReply
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ThreadLocalRandom

class HttpProbe(private val ctx: Ctx) {
    suspend fun run() {
        reach()
        plaintextCanary()
        headerFingerprint()
        protocolSupport()
        if (ctx.opts.mode != Mode.QUICK) throughput()
    }

    private suspend fun reach() {
        val c = ctx.reg.add(Check("http.reach", "http", "HTTP-доступность"))
        val t = Targets.load(ctx.opts.extraDomains)
        val domains = (t.control.take(3) + t.suspect.take(if (ctx.opts.mode == Mode.QUICK) 5 else 10)).distinct()
        val res = parMap(10, domains) { d ->
            val https = Http.get("https://$d/", 4500, maxBody = 4096)
            val http = Http.get("http://$d/", 4000, maxBody = 4096)
            Triple(d, https, http)
        }
        val dead = res.filter { it.second.status == 0 && it.third.status == 0 }
        val bad = res.filter { it.second.status in listOf(403, 451, 503) || it.third.status in listOf(403, 451, 503) }
        val ok = res.count { it.second.status in 200..399 }
        when {
            dead.isNotEmpty() -> {
                c.set(Verdict.FAIL, "${dead.size} из ${domains.size} доменов недоступны по HTTP")
                dead.forEach { c.ev("  ${it.first}  →  https: ${it.second.error.take(40)}  http: ${it.third.error.take(40)}") }
            }
            bad.isNotEmpty() -> {
                c.set(Verdict.WARN, "${bad.size} домен(ов) отвечают 403/451")
                bad.forEach { c.ev("  ${it.first}  →  https ${it.second.status} / http ${it.third.status}") }
                ctx.blockers.add("HTTP 403/451 на ${bad.joinToString { it.first }}")
            }
            else -> c.set(Verdict.OK, "$ok/${domains.size} доменов отдают 2xx/3xx")
        }
        res.filter { it.second.status != 0 }.forEach { c.ev("  ${it.first.padEnd(24)} https ${it.second.status} ${it.second.ms} мс · http ${it.third.status}") }
    }

    private suspend fun plaintextCanary() {
        val c = ctx.reg.add(Check("http.canary", "http", "Политика в отношении открытого текста"))
        c.critical = true
        val r = Http.get("http://neverssl.com", 5000, maxBody = 200000)
        if (r.status != 200) {
            val blockedWords = r.text.contains("BLOCKED", true) || r.text.contains("ЗАБЛОКИРОВАН", true) ||
                    r.text.contains("ЗАПРЕЩЕН", true) || r.status in listOf(403, 451)
            c.set(if (blockedWords) Verdict.FAIL else Verdict.WARN,
                "http://neverssl.com → ${if (r.status > 0) "HTTP $r.status" else r.error.take(40)}")
            c.ev("открытый HTTP-трафик не доходит до получателя — это и есть быстрый способ цензуры")
            r.text.take(400).replace(Regex("\\s+"), " ").take(300).takeIf { it.isNotBlank() }?.let { c.ev("тело ответа: $it") }
            if (blockedWords) ctx.blockers.add("блокировка содержимого открытого HTTP (подмена на BLOCKED)")
        } else {
            val body = r.text
            val hasMarker = body.contains("NeverSSL", true) || body.contains("update your browser", true)
            val scripts = Regex("(?i)<script[^>]*src=[\"']([^\"']+)").findAll(body).map { it.groupValues[1] }.toList()
            val injected = scripts.filter { s -> s.contains("google-analytics", true) || s.contains("doubleclick", true) || s.contains("adservice", true) }
            c.set(
                when {
                    !hasMarker -> Verdict.WARN
                    injected.isNotEmpty() -> Verdict.WARN
                    else -> Verdict.OK
                },
                "страница отдалась как есть (${body.length} байт${if (hasMarker) ", маркер на месте" else ""})"
            )
            c.ev("проверяем, что оператор не подменяет содержимое открытого HTTP")
            if (injected.isNotEmpty()) c.ev("подозрительные скрипты в HTTP-странице: " + injected.joinToString())
        }
    }

    private suspend fun headerFingerprint() {
        val c = ctx.reg.add(Check("http.headers", "http", "Отпечаток HTTP-пути"))
        val host = Targets.load().control.firstOrNull() ?: "cloudflare.com"
        val https = Http.get("https://$host/", 5000, maxBody = 65536)
        val http = Http.get("http://$host/", 5000, maxBody = 65536)
        val proxyHeaders = listOf("Via", "X-Cache", "X-Forwarded-For", "X-Real-IP", "X-Proxy", "CF-Ray", "X-Cache-Hits", "Forwarded")
        val found = proxyHeaders.mapNotNull { h -> https.header(h).takeIf { it.isNotBlank() }?.let { "$h: $it" } }
        val httpsScripts = Regex("(?i)<script[^>]*src=[\"']([^\"']+)").findAll(https.text).map { it.groupValues[1] }.toSet()
        val httpScripts = Regex("(?i)<script[^>]*src=[\"']([^\"']+)").findAll(http.text).map { it.groupValues[1] }.toSet()
        val extraInPlain = httpScripts - httpsScripts

        c.set(Verdict.INFO, "https ${https.status}/${https.ms} мс · http ${http.status}/${http.ms} мс")
        if (https.server.isNotBlank()) c.ev("Server: ${https.server}")
        found.forEach { c.ev(it) }
        if (extraInPlain.isNotEmpty()) {
            c.set(Verdict.WARN, "в открытом HTTP есть скрипты, которых нет в HTTPS")
            extraInPlain.take(6).forEach { c.ev("лишний <script src>: $it") }
            ctx.blockers.add("внедрение скриптов в открытый HTTP")
        }
        if (http.status in 200..299 && http.location.isNotBlank()) {
            c.ev("http отвечает редиректом на ${http.location.take(70)}")
            if (!http.location.startsWith("https://$host")) c.ev("редирект ведёт на сторонний домен — повод присмотреться")
        }
    }

    private suspend fun protocolSupport() {
        val c = ctx.reg.add(Check("http.protocols", "http", "HTTP/2, HTTP/3 (QUIC) и UDP"))
        val host = Targets.load().control.firstOrNull() ?: "cloudflare.com"
        val h2 = Http.get("https://$host/", 5000, maxBody = 2048)
        c.ev("ALPN по умолчанию: ${h2.header("Alt-Svc").ifBlank { "не объявлен" }}")
        val quicHosts = Targets.load().quic.take(2)
        val quic = parMap(2, quicHosts) { q -> quicProbe(q) }
        val quicUp = quic.count { it.second }
        val udpGeneral = udpEcho(3478)
        when {
            quicUp == 0 -> {
                c.set(Verdict.WARN, "QUIC/UDP-443 не отвечает — UDP либо закрыт, либо режется")
                c.ev("полная блокировка UDP ломает QUIC, WebRTC, WireGuard и частично Tor")
                ctx.blockers.add("UDP/443 (QUIC) недоступен")
            }
            !udpGeneral -> {
                c.set(Verdict.WARN, "QUIC работает, но обычный UDP (3478) нет — эшелонированная фильтрация UDP")
            }
            else -> c.set(Verdict.OK, "QUIC/UDP-443 отвечает (${quicUp}/${quicHosts.size}), UDP в целом открыт")
        }
        quic.forEach { (h, up, ms) -> c.ev("  $h  UDP/443 → ${if (up) "ответ за $ms мс" else "тишина"}") }
    }

    private suspend fun throughput() {
        val c = ctx.reg.add(Check("http.speed", "http", "Скорость и асимметрия"))
        val urls = listOf(
            "https://speed.cloudflare.com/__down?bytes=8000000" to "Cloudflare",
            "https://speedtest.tele2.net/8MB.zip" to "Tele2",
            "https://proof.ovh.net/files/10Mb.dat" to "OVH"
        )
        val res = parMap(3, urls) { (u, n) -> n to Http.get(u, 12000, maxBody = 12 shl 20) }
        val good = res.mapNotNull { (n, r) ->
            val dt = if (r.bodyMs > 0) r.bodyMs else r.ms
            if (r.bytes > 200000 && dt > 0) Speed(n, r.bytes, r.bytes * 8.0 / dt, dt) else null
        }
        if (good.isEmpty()) {
            c.set(Verdict.SKIP, "не удалось замерить скорость (файлы недоступны)")
            res.forEach { (n, r) -> c.ev("$n → ${r.error.take(60).ifEmpty { "HTTP ${r.status}, ${r.bytes} Б" }}") }
            return
        }
        val best = good.maxByOrNull { it.mbit }!!
        val worst = good.minByOrNull { it.mbit }!!
        val ratio = if (worst.mbit > 0) best.mbit / worst.mbit else 0.0
        val v = when {
            best.mbit < 2000 -> Verdict.FAIL
            best.mbit < 8000 -> Verdict.WARN
            ratio > 8 -> Verdict.WARN
            else -> Verdict.OK
        }
        c.set(v, "до ${"%.1f".format(best.mbit / 1000)} Мбит/с (${best.name}), худший ${"%.1f".format(worst.mbit / 1000)} Мбит/с")
        good.forEach { s ->
            c.ev("  ${s.name.padEnd(12)} ${"%.2f".format(s.bytes / 1e6)} МБ за ${s.ms} мс → ${"%.1f".format(s.mbit / 1000)} Мбит/с")
        }
        if (ratio > 8) {
            c.ev("разброс скорости ×${"%.1f".format(ratio)} — быстрые CDN и медленный остальной интернет: типичный признак направленного замедления")
            ctx.blockers.add("асимметрия скорости ×${"%.1f".format(ratio)}")
        }
    }

    private data class Speed(val name: String, val bytes: Int, val mbit: Double, val ms: Long)

    private fun quicProbe(host: String, timeoutMs: Int = 2200): Triple<String, Boolean, Long> {
        val rnd = ThreadLocalRandom.current()
        return try {
            val t0 = System.nanoTime()
            val dcid = ByteArray(8).also { rnd.nextBytes(it) }
            val scid = ByteArray(8).also { rnd.nextBytes(it) }
            val header = ByteArrayOutputStream()
            header.write(0xC3)
            header.write(byteArrayOf(0, 0, 0, 1))
            header.write(8); header.write(dcid)
            header.write(8); header.write(scid)
            header.write(0)               // token length
            val payloadLen = 1200 - header.size() - 2 - 4
            header.write(varint(payloadLen + 4))
            header.write(byteArrayOf(0, 0, 0, 1))   // packet number
            val packet = header.toByteArray() + ByteArray(payloadLen)
            DatagramSocket().use { sock ->
                sock.soTimeout = timeoutMs
                sock.send(DatagramPacket(packet, packet.size, InetAddress.getByName(host), 443))
                val buf = ByteArray(2048)
                val pkt = DatagramPacket(buf, buf.size)
                sock.receive(pkt)
                Triple(host, true, (System.nanoTime() - t0) / 1_000_000)
            }
        } catch (_: Throwable) {
            Triple(host, false, timeoutMs.toLong())
        }
    }

    private fun udpEcho(port: Int, host: String = "stun.cloudflare.com"): Boolean = try {
        DatagramSocket().use { sock ->
            sock.soTimeout = 1800
            val q = ByteArray(4)
            sock.send(DatagramPacket(q, q.size, InetAddress.getByName(host), port))
            val buf = ByteArray(512)
            sock.receive(DatagramPacket(buf, buf.size))
            true
        }
    } catch (_: Throwable) { false }

    private fun varint(v: Int): ByteArray {
        return if (v < 64) byteArrayOf(v.toByte())
        else if (v < 16384) byteArrayOf((0x40 or (v shr 8)).toByte(), (v and 0xFF).toByte())
        else byteArrayOf((0x80 or (v shr 24)).toByte(), (v shr 16 and 0xFF).toByte(), (v shr 8 and 0xFF).toByte(), (v and 0xFF).toByte())
    }
}
