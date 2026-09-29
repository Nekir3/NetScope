package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Targets
import netscope.core.Verdict
import netscope.net.Dns
import netscope.net.DnsResponse
import netscope.net.DnsType
import netscope.net.NetError
import netscope.net.Proc
import netscope.net.classify
import netscope.net.nanoMs
import netscope.net.Doh
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.ThreadLocalRandom

class DnsProbe(private val ctx: Ctx) {
    private val domainSet: List<String>
    private val resolverMap: List<Pair<String, String>>

    init {
        val t = Targets.load(ctx.opts.extraDomains)
        domainSet = (t.control + t.suspect).distinct().take(if (ctx.opts.mode == netscope.core.Mode.QUICK) 4 else 8)
        resolverMap = Targets.publicResolvers
    }

    suspend fun run() {
        systemResolvers()
        val reference = dohReference()
        honesty(reference)
        wildcard(reference)
        sinkhole()
        resolverIdentity()
        transparentInterception()
        ednsAndCase()
        dotAndDoh()
    }

    private fun systemResolvers() {
        val c = ctx.reg.add(Check("dns.system", "dns", "Системные резолверы"))
        val r = Proc.console("ipconfig /all", 12000)
        val list = parseResolvers(r.text)
        if (list.isEmpty()) {
            c.set(Verdict.INFO, "не определены (резолвер на уровне ОС)")
            c.ev("ipconfig не отдал список — probable DHCP/WPAD или без админских прав")
        } else {
            ctx.systemResolvers.addAll(list)
            val labels = list.map { ip -> resolverMap.firstOrNull { it.first == ip }?.second ?: ip }
            c.set(Verdict.INFO, "${list.size}: ${labels.take(4).joinToString()}")
            c.ev(labels.joinToString("\n"))
        }
    }

    private suspend fun dohReference(): Map<String, List<String>> {
        val c = ctx.reg.add(Check("dns.doh", "dns", "Эталон через DoH"))
        val probe = "cloudflare.com"
        val servers = listOf(Doh.default[0], Doh.default[1], Doh.default[2])
        data class Row(val resp: DnsResponse, val name: String, val ms: Long)
        val results = parMap(3, servers) { s ->
            val t0 = nanoMs()
            runCatching { Row(Doh.query(s, probe, DnsType.A, 4500), s.name, nanoMs() - t0) }
        }
        val ok = results.mapNotNull { it.getOrNull() }.filter { it.resp.rcode == 0 && it.resp.v4.isNotEmpty() }
        val ref: Map<String, List<String>> = ok.groupBy({ it.resp.v4.sorted().joinToString(",") }, { it.name })
            .mapValues { (_, v) -> v.toList() }
        val failed = results.size - ok.size
        if (ok.isEmpty()) {
            c.set(Verdict.FAIL, "DoH полностью недоступен — не с чем сравнивать")
            c.ev("Cloudflare, Google и Quad9 не ответили: HTTPS, вероятно, тоже фильтруется")
        } else if (ok.size <= 1) {
            c.set(Verdict.WARN, "DoH отвечает только ${ok[0].name} (${ok[0].resp.v4.joinToString()})")
            c.ev("остальные DoH-сервисы: ошибка или фильтрация, неудачных = $failed")
        } else {
            c.set(Verdict.OK, "${ok.size} DoH-сервера подтвердили ${ok[0].resp.v4.joinToString()}")
            ok.forEach { c.ev("${it.name.padEnd(12)} ${it.resp.v4.joinToString(", ")}  (${it.ms} мс)") }
        }
        ctx.head.resolver = ctx.systemResolvers.firstNotNullOfOrNull { ip ->
            resolverMap.firstOrNull { it.first == ip }?.second
        } ?: "неизвестен"
        return ref
    }

    private suspend fun honesty(reference: Map<String, List<String>>) {
        val c = ctx.reg.add(Check("dns.honesty", "dns", "Честность ответов DNS"))
        c.critical = true
        if (reference.isEmpty()) { c.set(Verdict.SKIP, "нет DoH-эталона"); return }
        val truth = reference.keys.first().split(",")
        val resolvers = (ctx.systemResolvers + listOf("1.1.1.1", "8.8.8.8")).distinct().take(6)
        val mismatches = mutableListOf<String>()
        val systemAnswers = mutableListOf<String>()
        val all = parMap(minOf(8, resolvers.size * domainSet.size).coerceAtLeast(1), resolvers.flatMap { s -> domainSet.map { s to it } }) { (srv, dom) ->
            val direct = runCatching { Dns.queryUdp(srv, 53, dom, DnsType.A, 2500) }.getOrNull()?.v4 ?: emptyList()
            val sys = systemLookup(dom)
            if (direct.isNotEmpty() && !overlaps(direct, truth)) {
                mismatches.add("$srv: $dom → ${direct.joinToString()} (эталон ${truth.joinToString()})")
            }
            sys to direct
        }
        all.forEach { systemAnswers.addAll(it.first) }
        val extra = systemAnswers.filter { it !in truth && !it.isPrivateV4() }
        when {
            mismatches.isNotEmpty() -> {
                c.set(Verdict.FAIL, "${mismatches.size} расхождений с DoH-эталоном")
                mismatches.take(12).forEach { c.ev(it) }
                ctx.blockers.add("подмена DNS-ответов")
            }
            extra.isNotEmpty() -> {
                c.set(Verdict.WARN, "резолверы отдают лишние адреса (${extra.size})")
                extra.distinct().take(8).forEach { c.ev("лишний A: $it") }
            }
            else -> c.set(Verdict.OK, "ответы совпали с эталоном (${domainSet.size} доменов × ${resolvers.size} резолверов)")
        }
        c.ev("эталон DoH: ${truth.joinToString(", ")}")
    }

    private fun overlaps(a: List<String>, b: List<String>) = a.any { it in b }

    private suspend fun systemLookup(domain: String): List<String> = withContext(Dispatchers.IO) {
        runCatching {
            java.net.InetAddress.getAllByName(domain).map { it.hostAddress ?: "" }.filter { it.isNotEmpty() }
        }.getOrDefault(emptyList())
    }

    private suspend fun wildcard(reference: Map<String, List<String>>) {
        val c = ctx.reg.add(Check("dns.wildcard", "dns", "Заглушки на произвольные имена"))
        val rnd = ThreadLocalRandom.current()
        val probes = listOf(
            rnd.nextLong().toString(16).take(16) + ".cloudflare.com",
            rnd.nextLong().toString(16).take(16) + ".example-netscope-probe.test",
            "nxdomain-test-" + rnd.nextInt(100000) + ".wikipedia.org"
        )
        val hits = par(3) { i ->
            val t0 = nanoMs()
            val direct = runCatching { Dns.queryUdp("1.1.1.1", 53, probes[i], DnsType.A, 2500) }.getOrNull()
            val sys = runCatching { Dns.queryUdp("8.8.8.8", 53, probes[i], DnsType.A, 2500) }.getOrNull()
            val d = (direct?.addresses ?: emptyList())
            val s = (sys?.addresses ?: emptyList())
            probes[i] to (d + s)
        }
        val answered = hits.filter { it.second.isNotEmpty() }
        if (answered.isEmpty()) {
            c.set(Verdict.OK, "несуществующие имена честно получают NXDOMAIN")
        } else {
            c.set(Verdict.FAIL, "резолвер отвечает на несуществующие имена — подмена DNS")
            answered.forEach { (n, a) -> c.ev("$n → ${a.joinToString(", ")}") }
            ctx.blockers.add("DNS-заглушка (wildcard)")
        }
    }

    private suspend fun sinkhole() {
        val c = ctx.reg.add(Check("dns.sinkhole", "dns", "Доменные блокировки"))
        val suspects = Targets.load(ctx.opts.extraDomains).suspect.take(if (ctx.opts.mode == netscope.core.Mode.QUICK) 4 else 10)
        val res = par(minOf(8, suspects.size)) { i ->
            val d = suspects[i]
            val viaDirect = runCatching { Dns.queryUdp("1.1.1.1", 53, d, DnsType.A, 2500) }.getOrNull()
            val viaSystem = systemLookup(d)
            Triple(d, viaDirect, viaSystem)
        }
        val blocked = res.filter { (_, direct, sys) ->
            (direct == null || direct.v4.isEmpty()) && sys.isEmpty()
        }
        val sink = res.filter { (_, direct, sys) ->
            (direct?.v4.orEmpty() + sys).any { isSinkhole(it) }
        }
        val total = res.size
        when {
            blocked.size == total && total > 0 -> c.set(Verdict.FAIL, "все $total доменов не разрешаются")
            blocked.isNotEmpty() -> c.set(Verdict.WARN, "${blocked.size} из $total доменов не разрешаются")
            else -> c.set(Verdict.OK, "все $total проверяемых доменов разрешаются через публичный резолвер")
        }
        blocked.forEach { (d, _, _) -> c.ev("$d — NXDOMAIN/таймаут даже у 1.1.1.1"); ctx.blockers.add("домен $d не резолвится") }
        sink.forEach { (d, _, sys) -> c.ev("$d → ${sys.joinToString(", ")} (адрес-заглушка)"); ctx.blockers.add("DNS-заглушка для $d") }
        if (blocked.isEmpty() && sink.isEmpty()) c.ev("проверено: " + suspects.joinToString(", "))
    }

    private fun isSinkhole(ip: String): Boolean {
        val p = ip.split('.').mapNotNull { it.toIntOrNull() }
        if (p.size != 4) return false
        return when {
            p[0] == 0 || p[0] == 127 || p[0] >= 240 -> true
            p[0] == 10 -> true
            p[0] == 172 && p[1] in 16..31 -> true
            p[0] == 192 && p[1] == 168 -> true
            p[0] == 169 && p[1] == 254 -> true
            p[0] == 100 && p[1] in 64..127 -> true
            p[0] == 198 && p[1] in 18..19 -> true
            p[0] >= 224 -> true
            else -> false
        }
    }

    private fun String.isPrivateV4(): Boolean {
        val p = split('.').mapNotNull { it.toIntOrNull() }
        if (p.size != 4) return false
        return p[0] == 127 || p[0] == 10 || (p[0] == 172 && p[1] in 16..31) || (p[0] == 192 && p[1] == 168)
    }

    private suspend fun resolverIdentity() {
        val c = ctx.reg.add(Check("dns.identity", "dns", "Кто фактически резолвит"))
        val name = "whoami.akamai.net"
        val viaSystem = runCatching { Dns.queryUdp((ctx.systemResolvers.firstOrNull() ?: "1.1.1.1"), 53, name, DnsType.T, 3000) }.getOrNull()
        val viaDirect = runCatching { Dns.queryUdp("1.1.1.1", 53, name, DnsType.T, 3000) }.getOrNull()
        val viaSystemA = runCatching { Dns.queryUdp((ctx.systemResolvers.firstOrNull() ?: "1.1.1.1"), 53, name, DnsType.A, 3000) }.getOrNull()
        val sysTxt = viaSystem?.txts?.firstOrNull()
        val dirTxt = viaDirect?.txts?.firstOrNull()
        val sysIp = viaSystemA?.v4?.firstOrNull()
        if (sysTxt == null && sysIp == null) {
            c.set(Verdict.SKIP, "Akamai whoami недоступен (фильтруется или домен не резолвится)")
        } else if (dirTxt != null && sysTxt != null && !sysTxt.contains(dirTxt) && !dirTxt.contains(sysTxt)) {
            c.set(Verdict.WARN, "система и прямой запрос видят разные резолверы — есть посредник")
            c.ev("система: $sysTxt"); c.ev("напрямую: $dirTxt")
        } else {
            c.set(Verdict.INFO, "резолвер оператора: ${sysIp ?: sysTxt}")
            c.ev("Whoami через систему: ${sysIp ?: sysTxt}")
            c.ev("Whoami напрямую к 1.1.1.1: ${dirTxt ?: "—"}")
        }
    }

    private suspend fun transparentInterception() {
        val c = ctx.reg.add(Check("dns.transparent", "dns", "Перехват DNS-трафика"))
        // TEST-NET-3 (RFC 5737) не маршрутизируется: ответ может прийти только от посредника
        val blackholes = listOf("203.0.113.53", "198.51.100.53")
        val intercepted = mutableListOf<String>()
        par(2) { i ->
            val srv = blackholes[i]
            val t0 = nanoMs()
            val r = runCatching { Dns.queryUdp(srv, 53, "example.com", DnsType.A, 1600) }
            val ms = nanoMs() - t0
            if (r.isSuccess) intercepted.add("$srv:53 → ответ за $ms мс")
        }
        // нестандартный порт на настоящем резолвере
        val weird = runCatching { Dns.queryUdp("8.8.8.8", 5353, "example.com", DnsType.A, 1600) }
        if (weird.isSuccess) intercepted.add("8.8.8.8:5353 (не-DNS порт) → ответ")

        if (intercepted.isEmpty()) {
            c.set(Verdict.OK, "поддельных ответов на несуществующие резолверы нет")
        } else {
            c.set(Verdict.FAIL, "DNS-трафик перехватывается прозрачно")
            intercepted.forEach { c.ev(it) }
            ctx.blockers.add("прозрачный перехват DNS")
        }
        c.ev("метод: запросы на RFC 5737 TEST-NET и нестандартный порт")
    }

    private suspend fun ednsAndCase() {
        val c = ctx.reg.add(Check("dns.edns", "dns", "EDNS0 и 0x20-кодирование"))
        val mixed = "ClOuDfLaRe.CoM"
        val plain = runCatching { Dns.queryUdp("1.1.1.1", 53, "cloudflare.com", DnsType.A, 2500, ednsUdpSize = 0) }.getOrNull()
        val withEdns = runCatching { Dns.queryUdp("1.1.1.1", 53, "cloudflare.com", DnsType.A, 2500, ednsUdpSize = 4096) }.getOrNull()
        val case = runCatching { Dns.queryUdp("1.1.1.1", 53, mixed, DnsType.A, 2500) }.getOrNull()
        val ednsOk = withEdns != null && !withEdns.truncated
        val caseOk = case != null && case.question.equals(mixed, ignoreCase = false)
        val bits = mutableListOf<String>()
        bits.add(if (ednsOk) "EDNS0/4096 поддерживается" else "EDNS0: ответ обрезан или не поддержан")
        bits.add(if (caseOk) "0x20-кодирование имени поддерживается" else "0x20-кодирование: имя отражено как есть")
        c.set(if (ednsOk && caseOk) Verdict.OK else Verdict.INFO, bits.joinToString("; "))
        c.ev("это признаки «честного» современного резолвера за пределами сети провайдера")
        plain?.let { c.ev("базовый ответ: ${it.statusText()}") }
    }

    private suspend fun dotAndDoh() {
        val c = ctx.reg.add(Check("dns.secure", "dns", "Защищённый DNS (DoT 853 / DoT443)"))
        val dot = runCatching { dotQuery("1.1.1.1", 853, "cloudflare.com", DnsType.A, "one.one.one.one", 4000) }
        val dotAlt = if (dot.isFailure) runCatching { dotQuery("1.1.1.1", 853, "cloudflare.com", DnsType.A, null, 4000) } else dot
        val ok = dotAlt.getOrNull()
        if (ok != null && ok.v4.isNotEmpty()) {
            c.set(Verdict.OK, "DNS-over-TLS работает, ответ ${ok.v4.joinToString()}")
            c.ev("TLS-туннель к 1.1.1.1:853 не фильтруется по SNI")
        } else {
            val reason = dotAlt.exceptionOrNull()?.message ?: "нет ответа"
            c.set(Verdict.WARN, "DoT недоступен: ${reason.take(70)}")
            c.ev("нетранспортный DNS (UDP 53) при этом может быть перехвачен")
        }
    }

    private fun dotQuery(ip: String, port: Int, name: String, type: Int, sni: String?, timeoutMs: Int): DnsResponse {
        val ctxSsl = javax.net.ssl.SSLContext.getInstance("TLS")
        ctxSsl.init(null, arrayOf(TrustNothing), java.security.SecureRandom())
        val s = ctxSsl.socketFactory.createSocket() as javax.net.ssl.SSLSocket
        val p = s.sslParameters
        if (sni != null) runCatching { p.serverNames = listOf(javax.net.ssl.SNIHostName(sni)) }
        p.endpointIdentificationAlgorithm = null
        s.sslParameters = p
        s.connect(InetSocketAddress(ip, port), timeoutMs)
        s.soTimeout = timeoutMs
        s.startHandshake()
        s.use {
            val q = Dns.buildQuery(name, type)
            val out0 = it.getOutputStream()
            out0.write(q)
            out0.flush()
            val inp = it.getInputStream()
            val head = ByteArray(2)
            readFully(inp, head)
            val len = ((head[0].toInt() and 0xFF) shl 8) or (head[1].toInt() and 0xFF)
            val body = ByteArray(len)
            readFully(inp, body)
            return Dns.parse(body, name, type)
        }
    }

    private fun readFully(inp: java.io.InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = inp.read(buf, off, buf.size - off)
            if (n < 0) throw java.io.IOException("поток закрыт на ${buf.size - off} байтах")
            off += n
        }
    }

    private object TrustNothing : javax.net.ssl.X509TrustManager {
        override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
    }

    private fun parseResolvers(text: String): List<String> {
        val res = mutableListOf<String>()
        val ipOnly = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        var inDns = false
        for (line in text.lineSequence()) {
            val t = line.trim()
            if (t.startsWith("DNS", true) || t.lowercase().contains(" dns") || t.contains("-dns", true) || t.lowercase().startsWith("dns")) {
                if (ipOnly.matches(t)) res.add(t) else inDns = true
                continue
            }
            if (t.isEmpty()) { inDns = false; continue }
            if (inDns && ipOnly.matches(t)) { res.add(t); continue }
            if (inDns) inDns = false
        }
        return res.filter { it != "0.0.0.0" && it != "255.255.255.255" }.distinct()
    }
}
