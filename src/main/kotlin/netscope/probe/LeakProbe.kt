package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Json
import netscope.core.Mode
import netscope.core.Targets
import netscope.core.Verdict
import netscope.net.Dns
import netscope.net.DnsType
import netscope.net.Http
import netscope.net.Stun
import java.net.Inet6Address

class LeakProbe(private val ctx: Ctx) {
    suspend fun run() {
        publicAddress()
        dnsLeak()
        webrtc()
        ipv6()
    }

    private suspend fun publicAddress() {
        val c = ctx.reg.add(Check("leak.ip", "leaks", "Внешний IP-адрес"))
        val results = mutableListOf<Pair<String, String>>()

        // DNS-путь: работает даже при блокировке HTTPS
        val dnsChecks = listOf(
            "OpenDNS" to Triple("resolver1.opendns.com", "myip.opendns.com", DnsType.A),
            "Google" to Triple("ns1.google.com", "o-o.myaddr.l.google.com", DnsType.TXT),
            "Akamai" to Triple("", "whoami.dsl.akamai.net", DnsType.A)
        )
        parMap(3, dnsChecks) { (name, spec) ->
            val r = runCatching {
                if (spec.first.isEmpty()) Dns.queryUdp("1.1.1.1", 53, spec.second, spec.third, 3000)
                else Dns.queryUdp(spec.first, 53, spec.second, spec.third, 3000)
            }.getOrNull()
            val ip = r?.txts?.firstOrNull()?.trim() ?: r?.v4?.firstOrNull() ?: ""
            if (ip.isNotBlank()) results.add(name to ip)
        }

        val services = Targets.load().egress.take(if (ctx.opts.mode == Mode.QUICK) 3 else 5)
        parMap(5, services) { url ->
            val r = Http.get("https://$url", 5000, maxBody = 4096)
            val ip = Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b|\\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\\b")
                .find(r.text)?.value?.trimEnd('.') ?: ""
            if (ip.isNotBlank()) results.add(url to ip)
        }

        val v4 = results.map { it.second }.filter { !it.contains(':') }.distinct()
        val v6 = results.map { it.second }.filter { it.contains(':') }.distinct()
        ctx.publicIpV4 = v4.firstOrNull() ?: ""
        ctx.publicIpV6 = v6.firstOrNull() ?: ""
        ctx.head.publicIp = ctx.publicIpV4.ifEmpty { "не определён" }
        if (ctx.publicIpV4.isNotBlank()) ctx.head.publicIpNote = "IPv6: " + (ctx.publicIpV6.ifEmpty { "нет" })

        when {
            results.isEmpty() -> c.set(Verdict.SKIP, "ни один сервис не ответил — сеть сильно ограничена")
            v4.size > 1 -> {
                c.set(Verdict.FAIL, "разные сервисы видят разный IPv4 (${v4.size} вариантов)")
                results.forEach { (n, ip) -> c.ev("  ${n.padEnd(28)} $ip") }
                ctx.blockers.add("подмена исходящего IP между сервисами")
            }
            v6.isNotEmpty() && !v6.contains(ctx.publicIpV4) && v4.isNotEmpty() -> {
                c.set(Verdict.WARN, "IPv4 и IPv6 ведут себя по-разному — есть риск утечки через IPv6")
                results.forEach { (n, ip) -> c.ev("  ${n.padEnd(28)} $ip") }
            }
            else -> {
                c.set(Verdict.OK, "все ${results.size} источников показали один адрес")
                results.forEach { (n, ip) -> c.ev("  ${n.padEnd(28)} $ip") }
            }
        }
        if (ctx.publicIpV4.isNotBlank()) {
            val priv = ctx.publicIpV4.split('.').firstOrNull()?.toIntOrNull()
            if (priv != null && (priv == 10 || priv == 127 || (priv == 172))) {
                c.set(Verdict.FAIL, "во внешнем адресе осталась приватная сеть — виден внутренний адрес")
            }
        }
    }

    private suspend fun dnsLeak() {
        val c = ctx.reg.add(Check("leak.dns", "leaks", "Утечка через DNS"))
        val r = runCatching { Dns.queryUdp("1.1.1.1", 53, "whoami.akamai.net", DnsType.A, 3000) }.getOrNull()
        val resolverIp = r?.v4?.firstOrNull() ?: ""
        val viaOp = runCatching { Dns.queryUdp((ctx.systemResolvers.firstOrNull() ?: "1.1.1.1"), 53, "whoami.akamai.net", DnsType.A, 3000) }
            .getOrNull()?.v4?.firstOrNull() ?: ""
        c.set(
            when {
                resolverIp.isEmpty() -> Verdict.SKIP
                viaOp.isNotEmpty() && !viaOp.equals(resolverIp, true) -> Verdict.INFO
                else -> Verdict.OK
            },
            "резолвер оператора: ${viaOp.ifBlank { "не определён" }} · эталон Cloudflare: ${resolverIp.ifBlank { "—" }}"
        )
        c.ev("если ваш адрес совпадает с адресом резолвера, DNS-запросы не уходят к провайдеру")
        c.ev("приватные адреса в Whoami означают, что оператор подменяет ответы Whoami")
        if (resolverIp.isNotEmpty() && ctx.publicIpV4.isNotEmpty() && resolverIp == ctx.publicIpV4) {
            c.ev("резолвер и внешний IP совпадают (${resolverIp}) — это норма для домашнего NAT")
        }
        val envLeak = listOf("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NS_PROXY").mapNotNull { k -> System.getenv(k)?.let { "$k=$it" } }
        if (envLeak.isNotEmpty()) c.ev("через окружение: " + envLeak.joinToString())
    }

    private suspend fun webrtc() {
        val c = ctx.reg.add(Check("leak.webrtc", "leaks", "WebRTC / STUN"))
        val servers = listOf(Stun.google, Stun.cloudflare, Stun.nextcloud)
        val res = parMap(3, servers) { s -> s to Stun.binding(s, 2500) }
        val ok = res.filter { it.second.ok && it.second.mappedAddress.isNotBlank() }
        if (ok.isEmpty()) {
            val errs = res.map { "${it.first.name}: ${it.second.error}" }.distinct()
            c.set(Verdict.WARN, "STUN не отвечает — ICE-механизм браузера не сможет определить адрес")
            errs.forEach { c.ev("  $it") }
            c.ev("заблокированный STUN обычно означает и блокировку WebRTC-трафика в целом")
        } else {
            val mapped = ok.map { it.second.mappedAddress }.distinct()
            val same = mapped.all { it == ctx.publicIpV4 }
            c.set(
                when {
                    mapped.size > 1 -> Verdict.WARN
                    !ctx.publicIpV4.isBlank() && !same -> Verdict.FAIL
                    else -> Verdict.OK
                },
                "STUN видит: ${mapped.joinToString(", ")}"
            )
            if (ctx.publicIpV4.isNotBlank() && !same) {
                c.ev("HTTP-переход показывает ${ctx.publicIpV4}, а STUN — ${mapped.joinToString()}: это и есть утечка реального адреса через WebRTC")
                ctx.blockers.add("утечка адреса через WebRTC/STUN")
            } else {
                c.ev("адрес, который увидит любой сайт в браузере, совпадает с обычным — утечки нет")
            }
            res.forEach { (s, r) -> c.ev("  ${s.name.padEnd(12)} ${r.mappedAddress.ifBlank { r.error }} ${r.ms} мс") }
        }
    }

    private suspend fun ipv6() {
        val c = ctx.reg.add(Check("leak.ipv6", "leaks", "IPv6 и туннели"))
        val r6 = Http.get("https://api64.ipify.org", 5000, maxBody = 512)
        val v6 = Regex("\\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\\b").find(r6.text)?.value
        val hasV6Link = withContext(Dispatchers.IO) {
            runCatching {
                java.net.NetworkInterface.getNetworkInterfaces().asSequence().toList()
                    .flatMap { it.inetAddresses.asSequence().toList() }
                    .any { n -> n is Inet6Address && !n.isLinkLocalAddress && !n.isLoopbackAddress }
            }.getOrDefault(false)
        }
        when {
            v6 != null && ctx.publicIpV4.isNotBlank() && !v6.startsWith(ctx.publicIpV4) -> {
                c.set(Verdict.WARN, "IPv6-адрес отличается от IPv4 — сайты увидят оба")
                c.ev("IPv4: ${ctx.publicIpV4}")
                c.ev("IPv6: $v6")
                c.ev("если VPN умеет только IPv4, трафик на api64 уйдёт мимо туннеля")
            }
            v6 != null -> c.set(Verdict.INFO, "IPv6 работает, адрес $v6")
            hasV6Link -> c.set(Verdict.WARN, "есть IPv6-интерфейс, но внешний адрес получить не удалось — возможен, утечка не исключена")
            else -> c.set(Verdict.OK, "IPv6 не используется — дырок через него нет")
        }
        if (v6 != null) ctx.publicIpV6 = v6
        if (hasV6Link) c.ev("наличие глобального IPv6 на интерфейсе: да (внешний адрес получить не вышло)")
        val ifaces = withContext(Dispatchers.IO) {
            runCatching {
                java.net.NetworkInterface.getNetworkInterfaces().asSequence().toList().mapNotNull { n ->
                    val v = n.interfaceAddresses.mapNotNull { ia -> ia.address?.hostAddress }
                        .filter { !it.startsWith("127.") && !it.startsWith("fe80") }
                    if (v.isEmpty()) null else "${n.displayName} [${n.name}] → ${v.joinToString()}"
                }
            }.getOrDefault(emptyList())
        }
        ifaces.forEach { c.ev("  $it") }
    }
}
