package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Json
import netscope.core.Mode
import netscope.core.Targets
import netscope.core.Verdict
import netscope.net.Doh
import netscope.net.DnsType
import netscope.net.Mitm
import netscope.net.Tls
import netscope.net.TlsInfo
import netscope.net.symbol

class TlsProbe(private val ctx: Ctx) {
    suspend fun run() {
        versions()
        certificates()
        sniVisibility()
        encryptedClientHello()
    }

    private suspend fun versions() {
        val c = ctx.reg.add(Check("tls.versions", "tls", "Поддержка версий TLS"))
        val host = Targets.load().control.firstOrNull() ?: "cloudflare.com"
        val targets = if (ctx.opts.mode == Mode.QUICK) listOf("TLSv1.2", "TLSv1.3") else listOf("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
        val res = parMap(4, targets) { p -> p to Tls.probe(host, 443, 5000, forcedProtocol = p, alpn = emptyList()) }
        res.forEach { (p, r) ->
            val mark = if (r.ok) netscope.ui.Glyph.ok() else netscope.ui.Glyph.fail()
            c.ev("  $mark ${p.padEnd(9)} ${if (r.ok) r.protocol + " " + r.cipherSuite else r.netError.symbol()}")
        }
        val ok = res.filter { it.second.ok }.map { it.first }
        val old = ok.filter { it == "TLSv1" || it == "TLSv1.1" }
        c.set(
            when {
                ok.isEmpty() -> Verdict.FAIL
                old.isNotEmpty() -> Verdict.WARN
                else -> Verdict.OK
            },
            "принимаются сервером: ${ok.joinToString(", ")}"
        )
        if (old.isNotEmpty()) {
            c.ev("сервер соглашается на устаревшие версии — трафик можно расшифровать")
            ctx.evidenceAll.add("сервер принимает ${old.joinToString()}")
        }
    }

    private suspend fun certificates() {
        val c = ctx.reg.add(Check("tls.certs", "tls", "Сертификаты и доверие"))
        val t = Targets.load(ctx.opts.extraDomains)
        val domains = (t.control.take(4) + t.suspect.take(if (ctx.opts.mode == Mode.QUICK) 3 else 6)).distinct()
        val res = parMap(6, domains) { d -> d to Tls.probe(d, 443, 5000) }
        val ok = res.filter { it.second.ok }
        ok.forEach { (_, i) -> i.leaf?.let { ctx.certsSeen[Mitm.sha256(it).take(23)] = it } }
        if (ok.isEmpty()) { c.set(Verdict.SKIP, "не удалось получить сертификаты"); return }
        val issuers = ok.map { it.second.issuer }.distinct()
        val markers = ok.flatMap { Mitm.matches(it.second.issuer + " " + it.second.subject) }.distinct()
        val untrusted = ok.filter { it.second.publiclyTrusted == false }
        val shortLived = ok.filter { it.second.daysLeft in 1..30 }
        when {
            markers.isNotEmpty() -> {
                c.set(Verdict.FAIL, "сертификат выпущен перехватывающим центром: ${markers.joinToString()}")
                ctx.blockers.add("MITM-сертификат: ${markers.joinToString()}")
            }
            untrusted.size == ok.size -> {
                c.set(Verdict.FAIL, "ни один сертификат не выдан публичным CA")
                c.ev(untrusted.first().second.trustError)
                ctx.blockers.add("сертификаты не проходят публичную проверку")
            }
            untrusted.isNotEmpty() -> {
                c.set(Verdict.WARN, "${untrusted.size} из ${ok.size} сертификатов не проходят публичную проверку")
                untrusted.forEach { (d, i) -> c.ev("  $d → ${i.trustError.take(90)}") }
                ctx.blockers.add("сертификат вне публичного CA: ${untrusted.joinToString { it.first }}")
            }
            else -> c.set(Verdict.OK, "${ok.size} сертификатов от публичных CA")
        }
        ok.forEach { (d, i) ->
            c.ev("  ${d.padEnd(22)} ${i.issuer.take(58)}")
            c.ev("      до ${i.notAfter}  (осталось ${i.daysLeft} дн.)  ${i.sigAlg}  ${i.pubKey}")
        }
        issuers.forEach { ctx.evidenceAll.add("CA: $it") }
        if (shortLived.isNotEmpty()) c.ev("короткоживущие сертификаты: ${shortLived.joinToString { it.first }} — бывает у перехватчиков")
    }

    private suspend fun sniVisibility() {
        val c = ctx.reg.add(Check("tls.sni", "tls", "Видимость SNI"))
        val host = Targets.load().control.firstOrNull() ?: "cloudflare.com"
        val ip = withContext(Dispatchers.IO) { runCatching { java.net.InetAddress.getByName(host).hostAddress }.getOrNull() }
        if (ip == null) { c.set(Verdict.SKIP, "нет адреса эталона"); return }
        val byName = Tls.probe(host, 443, 5000, sniOverride = host, verifyHostname = true)
        val noSni = Tls.probe(ip, 443, 5000, sniOverride = null, verifyHostname = false)
        val bogusSni = Tls.probe(ip, 443, 5000, sniOverride = "aaaa-netscope-probe.invalid", verifyHostname = false)
        c.ev("с SNI ${host}: ${if (byName.ok) byName.protocol else byName.error.take(50)}")
        c.ev("без SNI: ${if (noSni.ok) "ответил, сертификат " + noSni.issuer.take(50) else noSni.error.take(60)}")
        c.ev("с выдуманным SNI: ${if (bogusSni.ok) "принял (!) " + bogusSni.issuer.take(40) else bogusSni.error.take(60)}")
        when {
            bogusSni.ok -> {
                c.set(Verdict.WARN, "сервер принимает несуществующее имя — проверка SNI на сервере отключена")
                c.ev("полезный признак: DPI, доверяющий только такому ответу, можно обмануть пустым SNI")
            }
            !noSni.ok && byName.ok -> c.set(Verdict.OK, "SNI обязателен и проверяется сервером — видно любому, кто смотрит в поток")
            else -> c.set(Verdict.INFO, "поведение эталона: без SNI ${if (noSni.ok) "отвечает" else "отказывает"}")
        }
        c.ev("пока SNI не спрятан в ECH, имя домена читается из первых байт соединения")
    }

    private suspend fun encryptedClientHello() {
        val c = ctx.reg.add(Check("tls.ech", "tls", "Encrypted Client Hello (ECH)"))
        val rr = runCatching { Doh.query(Doh.default[0], "cloudflare-ech.com", DnsType.HTTPS, 4500) }.getOrNull()
        val deployed = rr?.answers?.any { it.type == DnsType.HTTPS } == true
        c.set(Verdict.INFO, if (deployed) "ECH развёрнут у Cloudflare, но этот клиент его не использует" else "ECH-конфигурация недоступна")
        c.ev("пока клиент не отправляет ECH, SNI виден оператору и любому DPI в пути")
        c.ev("включить ECH: Chrome 117+/Firefox 120+ с DoH, либо плагин браузера")
        if (deployed) c.ev("в ответе DNS найдена HTTPS/SVCB-запись с параметрами ECH")
    }
}
