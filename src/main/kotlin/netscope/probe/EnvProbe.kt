package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Json
import netscope.core.Verdict
import netscope.net.Proc
import netscope.net.nanoMs
import java.util.Locale

class EnvProbe(private val ctx: Ctx) {
    suspend fun run() {
        ctx.reg.add(Check("env.adapters", "env", "Сетевые адаптеры")).also { c ->
            val r = withContext(Dispatchers.IO) { Proc.powershell(PRE_PS_ADAPTERS, 12000) }
            val rows = Json.parse(r.out)
            val list = rows.asList()
            if (list.isEmpty()) {
                c.set(Verdict.SKIP, "не удалось получить список (нужны права администратора?)")
            } else {
                val v4 = list.filter { it.field("family")?.asString() == "IPv4" || it.field("IPAddress")?.asString()?.contains(':') == false }
                val iface = list.mapNotNull { it.field("interfaceAlias")?.asString() }.distinct()
                c.set(Verdict.INFO, "${iface.size} интерфейс(ов), ${v4.size} IPv4-адресов")
                list.forEach { e ->
                    c.ev("%s  %s/%s  gw=%s".format(
                        e.field("interfaceAlias")?.asString() ?: "?",
                        e.field("ipAddress")?.asString() ?: "?",
                        e.field("prefixLength")?.asString() ?: "?",
                        e.field("nextHop")?.asString() ?: "—"
                    ))
                }
                val suspicious = iface.filter { it.contains("VPN", true) || it.contains("TAP", true) || it.contains("TUN", true) || it.contains("Wintun", true) || it.contains("Loopback", true) }
                if (suspicious.isNotEmpty()) c.ev(" tuner/VPN: " + suspicious.joinToString(", "))
            }
        }

        ctx.reg.add(Check("env.proxy", "env", "Системный прокси")).also { c ->
            val r = withContext(Dispatchers.IO) { Proc.powershell(PRE_PS_PROXY, 10000) }
            val j = Json.parse(r.out)
            val enabled = j.field("ProxyEnable")?.asString() == "1" || j.field("ProxyEnable")?.asString()?.lowercase() == "true"
            val server = j.field("ProxyServer")?.asString()?.takeIf { it.isNotBlank() && it != "null" } ?: ""
            val pac = j.field("AutoConfigURL")?.asString()?.takeIf { it.isNotBlank() && it != "null" } ?: ""
            val envProxy = listOf("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY").mapNotNull { k ->
                System.getenv(k)?.let { "$k=$it" }
            }
            when {
                enabled && server.isNotBlank() -> {
                    c.set(Verdict.WARN, "весь трафик идёт через прокси $server")
                    c.ev("установленный прокси — потенциальная точка наблюдения за TLS")
                }
                pac.isNotBlank() -> c.set(Verdict.WARN, "включён автоконфиг прокси (PAC): $pac")
                envProxy.isNotEmpty() -> c.set(Verdict.WARN, "заданы переменные: ${envProxy.joinToString()}")
                else -> c.set(Verdict.OK, "системный прокси не настроен")
            }
            if (envProxy.isNotEmpty()) c.ev(envProxy.joinToString("  "))
        }

        val mtuCheck = ctx.reg.add(Check("env.mtu", "env", "MTU пути (Path MTU)"))
        mtuCheck.set(Verdict.RUN, "измеряем")
        val target = ctx.opts.mode.let { listOf("1.1.1.1", "8.8.8.8", "cloudflare.com").firstOrNull { pingOk(it, 32) } ?: "1.1.1.1" }
        val mtu = withContext(Dispatchers.IO) { findMtu(target) }
        if (mtu > 0) {
            ctx.mtuHost = target
            ctx.pathMtu = mtu
            when {
                mtu >= 1500 -> mtuCheck.set(Verdict.OK, "$mtu байт до $target — стандартный Ethernet, без усечения")
                mtu >= 1400 -> mtuCheck.set(Verdict.INFO, "$mtu байт — небольшая фрагментация/туннелирование")
                else -> mtuCheck.set(Verdict.WARN, "$mtu байт до $target — сильное усечение, вероятен прозрачный прокси")
            }
            mtuCheck.ev("ICMP DF-бит: payload ${mtu - 28} + 20 IP + 8 ICMP = $mtu")
            mtuCheck.set(mtuCheck.verdict, "${mtu} байт до $target " + mtuNote(mtu))
        } else {
            mtuCheck.set(Verdict.SKIP, "ICMP заблокирован, MTU недоступен")
        }

        ctx.reg.add(Check("env.tunnel", "env", "Туннели и IPv6")).also { c ->
            val teredo = withContext(Dispatchers.IO) { Proc.console("netsh interface ipv6 show teredo", 6000) }
            val routes = withContext(Dispatchers.IO) { Proc.console("route print -4", 6000) }
            val teredoOn = teredo.out.contains("Yes", true) || teredo.out.contains("Yes".uppercase(), true) ||
                    Regex("Client ID\\s*enabled\\s*:\\s*Yes", RegexOption.IGNORE_CASE).containsMatchIn(teredo.out)
            val server = Regex("Server\\s*:\\s*([0-9a-fA-F:.]+)", RegexOption.IGNORE_CASE).find(teredo.out)?.groupValues?.get(1)
            val privateRoutes = Regex("^\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+.*\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+.*\\s+(\\d+)")
                .findAll(routes.out).map { it.groupValues }.filter { it[3].toInt() <= 8 }.toList()
            val detail = buildString {
                if (teredoOn && server != null && !server.startsWith("0.0.0.0")) append("Teredo активен (server=$server) ")
                append("маршрутов с маской /${privateRoutes.firstOrNull()?.get(3) ?: "?"}: ${privateRoutes.size}")
            }
            c.set(if (teredoOn && server != null && !server.startsWith("0.0.0.0")) Verdict.WARN else Verdict.INFO, detail.trim())
            if (teredoOn) c.ev("Teredo маскирует реальный IPv4 — часть DPI-устройств его не видят, часть видит")
            privateRoutes.take(6).forEach { c.ev("сеть ${it[1]}/${it[3]} через ${it[2]}") }
        }

        if (ctx.opts.mode == netscope.core.Mode.DEEP) {
            ctx.reg.add(Check("env.trace", "env", "Трассировка маршрута")).also { c ->
                val host = ctx.opts.extraDomains.firstOrNull() ?: "cloudflare.com"
                val r = withContext(Dispatchers.IO) { Proc.tracert(host, 24, 800) }
                val hops = parseTracert(r.out)
                if (hops.isEmpty()) c.set(Verdict.SKIP, "tracert не дал результата (ICMP режут)")
                else {
                    val firstStar = hops.indexOfFirst { it.ms.isEmpty() }
                    val allStar = hops.count { it.ms.isEmpty() }
                    val text = "${hops.size} хопов, $allStar без ответа"
                    c.set(if (allStar > hops.size / 2) Verdict.WARN else Verdict.INFO, text)
                    hops.forEach { c.ev(("#${it.index}").padEnd(4) + (it.ip ?: "*").padEnd(18) + if (it.ms.isEmpty()) "—" else it.ms.joinToString(" / ") + " мс") }
                    if (firstStar in 1 until hops.size - 1) {
                        c.ev("первый «мёртвый» хоп: #${hops[firstStar].index} — типичное место DPI, но может быть и просто ICMP-фильтрация")
                    }
                }
            }
        }
    }

    private fun mtuNote(mtu: Int) = when {
        mtu >= 1500 -> "— стандартный Ethernet, усечения нет"
        mtu >= 1400 -> "— небольшая фрагментация, обычно VPN или туннель"
        else -> "— сильное усечение, типично для прозрачных прокси"
    }

    private fun pingOk(host: String, size: Int): Boolean {
        val r = Proc.ping(host, size, true, 1200)
        val t = r.text.lowercase(Locale.ROOT)
        return t.contains("ttl=") || (r.code == 0 && t.contains("bytes=") && !t.contains("needs to be fragmented"))
    }

    private fun findMtu(host: String): Int {
        var lo = 576
        var hi = 1500
        if (!pingOk(host, 1472)) {
            if (!pingOk(host, 576)) return -1
        } else {
            return 1500
        }
        while (hi - lo > 8) {
            val mid = (lo + hi) / 2
            val payload = mid - 28
            if (pingOk(host, payload)) lo = mid else hi = mid
        }
        return (lo + 8).coerceIn(576, 1500)
    }

    private fun parseTracert(out: String): List<Hop> {
        val re = Regex("^\\s*(\\d+)\\s+(.*)$")
        val hops = mutableListOf<Hop>()
        for (line in out.lineSequence()) {
            val m = re.find(line) ?: continue
            val idx = m.groupValues[1].toIntOrNull() ?: continue
            val rest = m.groupValues[2]
            val ip = Regex("(\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9a-fA-F:]{4,})").find(rest)?.groupValues?.get(1)
            val ms = Regex("<\\s*(\\d+)\\s*ms|(\\d+)\\s*ms").findAll(rest).mapNotNull {
                (it.groupValues.getOrNull(1) ?: it.groupValues.getOrNull(2))?.toIntOrNull()
            }.toList()
            if (ip == null && ms.isEmpty()) continue
            hops.add(Hop(idx, ip, ms))
        }
        return hops
    }

    data class Hop(val index: Int, val ip: String?, val ms: List<Int>)

    companion object {
        private const val PRE_PS_ADAPTERS =
            "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { \$_.IPAddress -notlike '127.*' -and \$_.IPAddress -notlike '169.254*' } | " +
                "Select-Object interfaceAlias,ipAddress,prefixLength,nextHop | ConvertTo-Json -Compress -Depth 2"
        private const val PRE_PS_PROXY =
            "try { Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' " +
                "| Select-Object ProxyEnable,ProxyServer,AutoConfigURL | ConvertTo-Json -Compress } catch { '{}' }"
    }
}
