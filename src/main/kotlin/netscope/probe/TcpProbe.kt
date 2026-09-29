package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Mode
import netscope.core.Targets
import netscope.core.Verdict
import netscope.net.NetError
import netscope.net.Tcp
import netscope.net.TcpOutcome
import netscope.net.nanoMs
import netscope.net.symbol

class TcpProbe(private val ctx: Ctx) {
    suspend fun run() {
        baseline()
        portMatrix()
        reachability()
        consistency()
    }

    private suspend fun baseline() {
        val c = ctx.reg.add(Check("tcp.baseline", "tcp", "Базовое соединение"))
        val hosts = Targets.load().control.take(4)
        val res = parMap(6, hosts) { Tcp.connect(it, 443, 3500) }
        val ok = res.filter { it.connected }
        if (ok.isEmpty()) {
            c.set(Verdict.FAIL, "ни один из ${hosts.size} хостов не принял соединение на 443")
            res.forEach { c.ev("${it.host}: ${it.error.symbol()} ${it.message.take(60)}") }
        } else {
            ctx.rttBaseline = ok.map { it.ms }.sorted()[ok.size / 2]
            val spread = ok.map { it.ms }
            c.set(Verdict.OK, "${ok.size}/${hosts.size} хостов, медианный RTT ${ctx.rttBaseline} мс")
            res.forEach {
                c.ev((if (it.connected) "  ok  " else "  ×   ") + "${it.host.padEnd(24)} ${it.error.symbol()} ${it.ms} мс  ${it.remoteAddr}")
            }
        }
    }

    private suspend fun portMatrix() {
        val c = ctx.reg.add(Check("tcp.ports", "tcp", "Фильтрация по портам"))
        val host = Targets.load().control.firstOrNull() ?: "cloudflare.com"
        val ip = runCatching { java.net.InetAddress.getByName(host).hostAddress }.getOrNull() ?: host
        val res = parMap(8, Targets.portMatrix) { port ->
            val t0 = nanoMs()
            val r = Tcp.connect(ip, port, 2600, label = "$ip:$port")
            Triple(port, r, nanoMs() - t0)
        }
        val open = res.filter { it.second.connected }.map { it.first }
        val refused = res.filter { !it.second.connected && (it.second.error == NetError.REFUSED || it.second.error == NetError.RESET) }.map { it.first }
        val dropped = res.filter { !it.second.connected && it.second.error == NetError.TIMEOUT }.map { it.first }
        val torPorts = setOf(9001, 9030, 9050, 1080, 8118, 8888)
        val torRefused = refused.filter { it in torPorts }
        val torDropped = dropped.filter { it in torPorts }
        val unusual = dropped.filter { it !in torPorts }

        val text = buildString {
            append("открыто ${open.size}")
            if (refused.isNotEmpty()) append(", RST ${refused.size}")
            if (dropped.isNotEmpty()) append(", тишина ${dropped.size}")
        }
        c.set(Verdict.INFO, text)
        res.forEach { (port, r, _) ->
            c.ev("  $port".padEnd(7) + (Targets.portService[port] ?: "").padEnd(14) +
                    (if (r.connected) "соединение " else r.error.symbol().padEnd(12)) + "${r.ms} мс")
        }
        when {
            torDropped.isNotEmpty() && torRefused.isNotEmpty() -> {
                c.set(Verdict.WARN, "Tor-порты ведут себя иначе, чем обычные: ${torDropped.joinToString()} — тишина, ${torRefused.joinToString()} — RST")
                ctx.blockers.add("избирательная фильтрация портов Tor")
            }
            torDropped.isNotEmpty() && unusual.isEmpty() -> {
                c.set(Verdict.WARN, "тишина именно на портах Tor/прокси: ${torDropped.joinToString()}")
                ctx.blockers.add("блокировка портов Tor/прокси")
            }
            dropped.isNotEmpty() -> c.ev("часть портов не отвечает (обычная политика брандмауэра)")
        }
    }

    private suspend fun reachability() {
        val c = ctx.reg.add(Check("tcp.reach", "tcp", "Достижимость доменов"))
        val targets = Targets.load(ctx.opts.extraDomains)
        val domains = (targets.control.take(3) + targets.suspect.take(if (ctx.opts.mode == Mode.QUICK) 5 else 10)).distinct()
        val res = parMap(10, domains) { d ->
            val h = Tcp.connect(d, 443, 3200)
            val p = Tcp.connect(d, 80, 3200)
            Triple(d, h, p)
        }
        val blocked = res.filter { !it.second.connected && it.third.connected }.map { it.first }
        val dead = res.filter { !it.second.connected && !it.third.connected }.map { it.first }
        val allOk = res.count { it.second.connected }
        when {
            blocked.isNotEmpty() -> {
                c.set(Verdict.FAIL, "${blocked.size} домен(ов): 443 закрыт, 80 открыт")
                blocked.forEach { c.ev("  $it  → 80 работает, 443 нет — типичная SNI/IP-фильтрация") }
                ctx.blockers.add("раздельная фильтрация 80/443 для ${blocked.joinToString()}")
            }
            dead.isNotEmpty() -> {
                c.set(Verdict.WARN, "${dead.size} домен(ов) не отвечают ни на 80, ни на 443")
                dead.forEach { c.ev("  $it  → 80: таймаут, 443: таймаут") }
                ctx.blockers.add("полная недоступность ${dead.joinToString()}")
            }
            else -> c.set(Verdict.OK, "$allOk/${domains.size} доменов доступны на 443")
        }
        c.ev("проверено: ${domains.size} доменов, таймаут 3.2 с")
    }

    private suspend fun consistency() {
        val c = ctx.reg.add(Check("tcp.jitter", "tcp", "Стабильность RTT"))
        val host = Targets.load().control.firstOrNull() ?: "cloudflare.com"
        val n = if (ctx.opts.mode == Mode.QUICK) 5 else 10
        val res = parMap(n, (0 until n).toList()) { Tcp.connect(host, 443, 3000) }
        val times = res.filter { it.connected }.map { it.ms }.sorted()
        if (times.isEmpty()) { c.set(Verdict.SKIP, "нет успешных соединений"); return }
        val min = times.first()
        val max = times.last()
        val med = times[times.size / 2]
        val spread = max - min
        val v = when {
            spread <= med / 4 -> Verdict.OK
            spread <= med -> Verdict.INFO
            else -> Verdict.WARN
        }
        c.set(v, "RTT $min…$max мс, медиана $med, разброс $spread мс (×${n})")
        c.ev("большой разброс на одинаковом маршруте — признак фрагментации, буферизации или DPI-очереди")
        c.ev("сырые: " + times.joinToString(", ") + " мс")
    }
}
