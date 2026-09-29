package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Json
import netscope.core.Mode
import netscope.core.Targets
import netscope.core.Verdict
import netscope.net.Http
import netscope.net.Mitm
import netscope.net.Proc
import netscope.net.Tls
import netscope.net.symbol
import java.security.cert.X509Certificate

class MitmProbe(private val ctx: Ctx) {
    suspend fun run() {
        issuerSpread()
        localRootStore()
        sessionSharing()
        contentIntegrity()
    }

    /**
     * Ключевой признак перехвата: один и тот же CA выпускает сертификаты
     * для несвязанных доменов из разных операторов.
     */
    private suspend fun issuerSpread() {
        val c = ctx.reg.add(Check("mitm.spread", "mitm", "Один CA на разные домены"))
        c.critical = true
        val domains = listOf("cloudflare.com", "www.google.com", "wikipedia.org", "github.com", "microsoft.com", "akamai.com")
        val res = parMap(6, domains) { d -> d to Tls.probe(d, 443, 5000) }
        val ok = res.filter { it.second.ok && it.second.leaf != null }
        if (ok.size < 3) { c.set(Verdict.SKIP, "мало успешных соединений"); return }
        val groups = ok.groupBy { it.second.issuer }
        val suspicious = groups.entries.filter { it.value.size >= 3 }
        val markers = ok.flatMap { Mitm.matches(it.second.issuer) }.distinct()
        c.set(
            when {
                markers.isNotEmpty() -> Verdict.FAIL
                suspicious.isNotEmpty() -> Verdict.FAIL
                else -> Verdict.OK
            },
            if (suspicious.isEmpty()) "${groups.size} разных CA на ${ok.size} доменов — картина нормальная"
            else "один CA выпустил сертификаты на ${suspicious[0].value.size} несвязанных доменов"
        )
        groups.forEach { (issuer, list) ->
            val flag = if (list.size >= 3) "!!" else "  "
            c.ev("$flag ${list.size}× ${issuer.take(80)}  →  ${list.joinToString { it.first }}")
        }
        if (markers.isNotEmpty()) {
            c.ev("маркеры перехвата: " + markers.joinToString())
            ctx.blockers.add("перехват TLS, CA: " + markers.joinToString())
        } else if (suspicious.isNotEmpty()) {
            ctx.blockers.add("единый CA на несвязанные домены")
        }
        res.filter { !it.second.ok }.forEach { (d, i) -> c.ev("  недоступен: $d — ${i.netError.symbol()}") }
    }

    private suspend fun localRootStore() {
        val c = ctx.reg.add(Check("mitm.rootstore", "mitm", "Локально установленные CA"))
        val r = withContext(Dispatchers.IO) { Proc.powershell(PS_ROOTS, 25000) }
        val json = Json.parse(r.out)
        val list = when (json) {
            is Json.Obj -> listOf(json)
            else -> json.asList()
        }
        if (list.isEmpty()) { c.set(Verdict.INFO, "список корневых CA пуст или недоступен"); return }
        val subjects = list.mapNotNull { it.field("Subject")?.asString() }
        val hits = subjects.filter { Mitm.matches(it).isNotEmpty() }
        val mitmHits = hits.mapNotNull { s -> Mitm.matches(s).firstOrNull()?.let { it to s } }
        c.set(
            when {
                mitmHits.isNotEmpty() -> Verdict.FAIL
                subjects.size > 80 -> Verdict.WARN
                else -> Verdict.INFO
            },
            "${subjects.size} корневых сертификатов в хранилище Windows${if (mitmHits.isNotEmpty()) ", из них подозрительных: ${mitmHits.size}" else ""}"
        )
        mitmHits.take(10).forEach { (marker, subj) -> c.ev("  подозрительный CA [$marker]: ${subj.take(90)}") }
        if (mitmHits.isEmpty()) subjects.take(5).forEach { c.ev("  · ${it.take(90)}") }
        c.ev("любой корень отсюда может выпустить сертификат, которому браузер доверяет без предупреждения")
        if (mitmHits.isNotEmpty()) ctx.blockers.add("в системном хранилище есть CA перехвата")
    }

    /** Обмен TLS-сессиями между разными доменами — признак общего терминатора. */
    private suspend fun sessionSharing() {
        val c = ctx.reg.add(Check("mitm.session", "mitm", "Общее состояние TLS-сессий"))
        val a = Tls.probe("cloudflare.com", 443, 5000)
        val b = Tls.probe("www.google.com", 443, 5000)
        if (!a.ok || !b.ok) { c.set(Verdict.SKIP, "нет соединений"); return }
        val sameIssuer = a.issuer.equals(b.issuer, ignoreCase = true)
        val sameCert = a.leaf?.encoded?.contentEquals(b.leaf?.encoded) == true
        when {
            sameCert -> {
                c.set(Verdict.FAIL, "разные домены отдают один и тот же сертификат")
                ctx.blockers.add("один сертификат на разные домены")
            }
            sameIssuer -> {
                c.set(Verdict.WARN, "домены из разных сетей подписаны одним CA")
                c.ev("cloudflare.com: ${a.issuer}")
                c.ev("google.com:    ${b.issuer}")
            }
            else -> c.set(Verdict.OK, "у каждого домена свой CA — признаков терминатора нет")
        }
        val alerts = parMap(2, listOf("cloudflare.com", "www.google.com")) { d -> d to Tls.probe(d, 443, 4000, forcedProtocol = "TLSv1.1") }
        val legacy = alerts.filter { it.second.ok }
        if (legacy.isNotEmpty()) c.ev("серверы идут на устаревший TLS 1.1 — можно включить расшифровку")
    }

    private suspend fun contentIntegrity() {
        val c = ctx.reg.add(Check("mitm.content", "mitm", "Целостность содержимого"))
        val pairs = listOf("example.com", "cloudflare.com", "wikipedia.org")
        val res = parMap(3, pairs) { d ->
            val h = Http.get("https://$d/", 5000, maxBody = 120000)
            val p = Http.get("http://$d/", 5000, maxBody = 120000)
            Triple(d, h, p)
        }
        val tampered = mutableListOf<String>()
        res.forEach { (d, h, p) ->
            if (h.status in 200..299 && p.status in 200..299) {
                val hs = Regex("(?i)<script[^>]*src=[\"']([^\"']+)").findAll(h.text).map { it.groupValues[1].lowercase() }.toSet()
                val ps = Regex("(?i)<script[^>]*src=[\"']([^\"']+)").findAll(p.text).map { it.groupValues[1].lowercase() }.toSet()
                val extra = ps - hs
                if (extra.isNotEmpty()) tampered.add("$d: в HTTP есть ${extra.size} лишних скриптов")
                val hl = h.header("Content-Length")
                val pl = p.header("Content-Length")
                if (hl.isNotBlank() && pl.isNotBlank() && hl != pl && p.body.size.toString() != hl) {
                    c.ev("$d: Content-Length HTTPS=$hl, HTTP=$pl, фактически ${p.body.size}")
                }
            }
        }
        if (tampered.isEmpty()) {
            c.set(Verdict.OK, "содержимое HTTP и HTTPS совпадает — подмены в открытом канале нет")
        } else {
            c.set(Verdict.FAIL, "найдена подмена содержимого в открытом HTTP")
            tampered.forEach { c.ev("  $it") }
            ctx.blockers.add("подмена содержимого HTTP")
        }
        res.forEach { (d, h, p) -> c.ev("  ${d.padEnd(16)} https ${h.status}/${h.bytes} байт · http ${p.status}/${p.bytes} байт") }
    }

    companion object {
        private const val PS_ROOTS =
            "Get-ChildItem Cert:\\CurrentUser\\Root, Cert:\\LocalMachine\\Root -ErrorAction SilentlyContinue " +
                "| Select-Object Subject | ConvertTo-Json -Compress -Depth 2"
    }
}
