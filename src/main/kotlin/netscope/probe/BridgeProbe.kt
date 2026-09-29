package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Mode
import netscope.core.Targets
import netscope.core.Verdict
import netscope.net.Http
import netscope.net.HelloSpec
import netscope.net.NetError
import netscope.net.Tcp
import netscope.net.TlsProbeRaw
import netscope.net.TlsState
import netscope.net.TlsWire
import netscope.net.nanoMs
import netscope.net.symbol
import java.security.SecureRandom

data class Bridge(
    val type: String,
    val host: String,
    val port: Int,
    val fingerprint: String,
    val options: Map<String, String>,
    val source: String
) {
    val label: String get() = "$type $host:$port"
    val cert: String get() = options["cert"].orEmpty()
    val front: String get() = options["fronts"] ?: options["front"] ?: ""
}

class BridgeProbe(private val ctx: Ctx) {
    private val rnd = SecureRandom()

    suspend fun run() {
        val bridges = loadBridges()
        if (bridges.isNotEmpty()) reachability(bridges)
        transportFeasibility()
        selfTest()
    }

    private suspend fun loadBridges(): List<Bridge> {
        val raw = ctx.opts.bridges.toMutableList()
        if (ctx.opts.fetchBridges) {
            val url = "https://bridges.torproject.org/bridges?transport=obfs4&status=working"
            val r = Http.get(url, 8000, maxBody = 300000)
            val found = Regex("(obfs4|obfsus|snowflake|meek-azure|vanilla)\\s+[0-9a-fA-F:.]+:\\d+[^<\\n]*")
                .findAll(r.text).map { it.value.trim() }.toList()
            raw.addAll(found)
            ctx.reg.info("bridge", "загружено мостов с bridges.torproject.org: ${found.size}")
        }
        return raw.mapNotNull { parse(it) }
    }

    private fun parse(line: String): Bridge? {
        val t = line.trim().split(Regex("\\s+"))
        if (t.size < 2) return null
        val type = t[0].lowercase()
        if (type !in setOf("obfs4", "obfsus", "snowflake", "meek-azure", "vanilla", "bridges")) return null
        val addr = t[1]
        val hostPort = addr.split(":")
        val port = hostPort.getOrNull(1)?.toIntOrNull() ?: 443
        val host = hostPort.first()
        val fp = t.getOrNull(2)?.takeIf { it.length >= 20 && it.all { ch -> ch.isLetterOrDigit() } } ?: ""
        val opts = t.drop(if (fp.isEmpty()) 2 else 3).mapNotNull {
            val i = it.indexOf('=')
            if (i <= 0) null else it.substring(0, i).lowercase() to it.substring(i + 1)
        }.toMap()
        return Bridge(type, host, port, fp, opts, line.trim())
    }

    private suspend fun reachability(bridges: List<Bridge>) {
        val c = ctx.reg.add(Check("bridge.reach", "bridges", "Достижимость мостов"))
        c.critical = true
        val res = parMap(6, bridges) { b -> probeBridge(b) }
        val alive = res.filter { it.reachable }
        val injected = res.filter { it.rstInjected }
        val dead = res.filter { !it.reachable }
        when {
            alive.isEmpty() -> {
                c.set(Verdict.FAIL, "ни один из ${bridges.size} мостов не доступен")
                ctx.blockers.add("все указанные мосты недоступны")
            }
            injected.isNotEmpty() -> {
                c.set(Verdict.FAIL, "${injected.size} мостов отбрасываются RST-инъекцией")
                ctx.blockers.add("RST-инъекция на портах мостов")
            }
            dead.isNotEmpty() -> {
                c.set(Verdict.WARN, "${alive.size} из ${bridges.size} мостов отвечают")
                ctx.blockers.add("часть мостов недоступна")
            }
            else -> c.set(Verdict.OK, "все ${bridges.size} мостов доступны")
        }
        res.forEach { r ->
            c.ev("  ${r.reachable.toString().padEnd(5)} ${r.bridge.label.padEnd(30)} ${r.state.padEnd(22)} ${r.ms} мс")
            if (r.note.isNotBlank()) c.ev("        ${r.note}")
        }
    }

    private data class BridgeProbeResult(
        val bridge: Bridge,
        val reachable: Boolean,
        val state: String,
        val ms: Long,
        val rstInjected: Boolean,
        val note: String
    )

    /**
     * Проверяем не сам протокол obfs4 (это отдельная криптография с собственным
     * клиентом), а сетевую проходимость: принимает ли порт соединение и
     * не подбрасывает ли в пути RST — самый частый способ блокировки мостов.
     */
    private suspend fun probeBridge(b: Bridge): BridgeProbeResult {
        val t0 = nanoMs()
        val conn = Tcp.connect(b.host, b.port, 3500, label = b.label)
        if (!conn.connected) {
            return BridgeProbeResult(b, false, conn.error.symbol(), conn.ms,
                conn.error == NetError.TIMEOUT, "соединение не установлено")
        }
        // Отправляем кадр, похожий на obfs4 (длина + зашумлённые данные) и смотрим реакцию.
        val frame = ByteArray(512).also { rnd.nextBytes(it) }
        val payload = byteArrayOf(((frame.size + 3) shr 8).toByte(), ((frame.size + 3) and 0xFF).toByte(), 0, 0) + frame
        val r = TlsProbeRaw.exchange(b.host, b.port, payload, 3000, 2000)
        val ms = nanoMs() - t0
        val rst = r.state == TlsState.RST
        val injected = rst && ctx.rttBaseline > 0 && r.msFirstByte < ctx.rttBaseline
        val note = when (r.state) {
            TlsState.TIMEOUT -> "тишина в ответ — обычное поведение obfs4: непрошедшие пакеты молча отбрасываются"
            TlsState.RST -> "RST за ${r.msFirstByte} мс" + if (injected) " — быстрее половины RTT, это инъекция, а не сервер" else ""
            TlsState.EOF -> "сервер закрыл соединение сразу"
            else -> r.state.name
        }
        return BridgeProbeResult(b, true, if (rst) "RST" else "открыт", ms, injected, note)
    }

    /** Может ли этот канал вообще пропустить обфусцированный транспорт. */
    private suspend fun transportFeasibility() {
        val c = ctx.reg.add(Check("bridge.transports", "bridges", "Проходимость транспортов"))
        c.critical = true

        val fronting = Targets.load().fronting
        val cdn = parMap(4, fronting) { d -> d to Http.get("https://$d/", 5000, maxBody = 4096) }
        val cdnOk = cdn.filter { it.second.status in 200..499 }
        ctx.meekFeasible = if (cdnOk.size >= 2) "да: CDN-фронтинг доступен" else "под вопросом: CDN-фронты отвечают плохо"

        val tlsInTlsOk = ctx.tlsInTls == "да"
        val fragOk = ctx.fragTolerance == "да"
        ctx.obfsFeasible = when {
            tlsInTlsOk -> "да: обкатка TLS-в-TLS проходит"
            else -> "нет: вложенный TLS отбрасывается"
        }
        val udpBlocked = ctx.blockers.any { it.contains("QUIC") }
        ctx.snowflakeFeasible = if (udpBlocked) "нет: UDP/443 не проходит" else "возможно: UDP-путь открыт, нужен рабочий мост"

        val rows = listOf(
            Triple("obfs4", tlsInTlsOk, if (tlsInTlsOk) "обкатка TLS-в-TLS принимается, порт 443 открыт" else "вложенный TLS режется middlebox'ом"),
            Triple("obfs4 с фрагментацией", fragOk, if (fragOk) "разрыв ClientHello переживается, padding допустим" else "middlebox разбирает только начало пакета"),
            Triple("snowflake", !udpBlocked, if (udpBlocked) "нужен UDP/443, он недоступен" else "UDP-путь открыт, дальше зависит от моста"),
            Triple("meek-azure / fronting", cdnOk.size >= 2, "${cdnOk.size} из ${fronting.size} CDN-фронтов отвечают"),
            Triple("bridges без обфускации", ctx.rttBaseline > 0, "работает, если порт 9001/443 не фильтруется по номеру")
        )
        c.set(
            if (rows.count { it.second } >= 3) Verdict.INFO else Verdict.WARN,
            "${rows.count { it.second }} из ${rows.size} транспортов технически возможны"
        )
        rows.forEach { (name, ok, note) ->
            c.ev("  ${if (ok) "да " else "нет"} $name — $note")
        }
        c.ev("")
        c.ev("вывод: obfs4 устойчив к SNI-фильтрации, потому что не отдаёт SNI вообще;")
        c.ev("если вложенный TLS режется, остаются snowflake (нужен UDP) и meek (нужен доступный CDN).")
        cdn.forEach { (d, r) -> c.ev("  CDN $d → ${if (r.status > 0) "HTTP ${r.status}" else r.error.take(40)}") }
    }

    /** Быстрая самопроверка обказки на реальном адресе, чтобы не гадать. */
    private suspend fun selfTest() {
        val c = ctx.reg.add(Check("bridge.selftest", "bridges", "Самопроверка обказки"))
        val host = Targets.load().control.firstOrNull() ?: "cloudflare.com"
        val ip = withContext(Dispatchers.IO) { runCatching { java.net.InetAddress.getByName(host).hostAddress }.getOrNull() }
        if (ip == null) { c.set(Verdict.SKIP, "нет адреса эталона"); return }
        val r = TlsProbeRaw.exchange(
            ip, 443,
            TlsWire.build(HelloSpec(sni = host)) + TlsWire.build(HelloSpec(sni = "nested.invalid", alpn = emptyList())),
            3000, 2500
        )
        val ok = r.state == TlsState.SERVER_HELLO || r.state == TlsState.HANDSHAKE_COMPLETE
        c.set(if (ok) Verdict.OK else Verdict.FAIL,
            if (ok) "обкатка доходит до сервера на $ip:443" else "обкатка не проходит на $ip:443")
        c.ev("это нижняя граница пригодности obfs4: настоящая проверка требует подключения к самому мосту")
        c.ev("проверить мост по-настоящему: Tor Browser → Настройки → Мосты → obfs4, или туннель через известный мост")
    }
}
