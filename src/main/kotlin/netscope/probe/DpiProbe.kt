package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Mode
import netscope.core.Targets
import netscope.core.Verdict
import netscope.net.HelloSpec
import netscope.net.TlsState
import netscope.net.TlsWire
import netscope.net.nanoMs
import netscope.net.symbol
import netscope.net.TlsProbeRaw
import java.net.IDN

class DpiProbe(private val ctx: Ctx) {
    private var goodIp: String = ""
    private var baselineRtt: Long = 0

    suspend fun run() {
        establishBaseline()
        sniBlacklist()
        rstInjection()
        obfuscationVariants()
        fragmentation()
        tlsInTls()
        ipLevel()
    }

    private suspend fun establishBaseline() {
        val c = ctx.reg.add(Check("dpi.baseline", "dpi", "Базовый TLS-хендшейк"))
        val hosts = Targets.load().control.take(3)
        val res = parMap(3, hosts) { h ->
            val t0 = nanoMs()
            val reply = TlsProbeRaw.exchange(h, 443, TlsWire.build(HelloSpec(sni = h)), 3000, 2500)
            Triple(h, reply, nanoMs() - t0)
        }
        val ok = res.filter { it.second.state == TlsState.SERVER_HELLO || it.second.state == TlsState.HANDSHAKE_COMPLETE }
        if (ok.isEmpty()) {
            c.set(Verdict.FAIL, "сырой ClientHello не получил ответа ни от одного эталона")
            res.forEach { c.ev("${it.first}: ${it.second.state} ${it.second.message.take(50)}") }
            return
        }
        val rtts = ok.map { it.second.msFirstByte }.sorted()
        baselineRtt = rtts[rtts.size / 2]
        ctx.rttBaseline = baselineRtt
        goodIp = ok.first().first
        c.set(Verdict.OK, "${ok.size}/${hosts.size} эталона ответили, RTT $baselineRtt мс, сервер ${ok.first().second.negotiated}")
        res.forEach { (h, r, _) ->
            c.ev("  ${h.padEnd(22)} ${r.state} · ${r.negotiated} · alpn=${r.alpn ?: "—"} · первый байт ${r.msFirstByte} мс" +
                    (if (r.alerts.isNotEmpty()) " · " + r.alerts.joinToString() else ""))
        }
    }

    private fun stateLabel(state: TlsState) = when (state) {
        TlsState.HANDSHAKE_COMPLETE -> "рукопожатие"
        TlsState.SERVER_HELLO -> "ответ сервера"
        TlsState.ALERT -> "alert сервера"
        TlsState.RST -> "TCP RST"
        TlsState.TIMEOUT -> "тишина"
        TlsState.EOF -> "разрыв"
        TlsState.CONNECT_FAILED -> "отказ"
        TlsState.PROTOCOL_ERROR -> "ошибка протокола"
    }

    private fun describe(r: netscope.net.TlsReply): String {
        val base = "${stateLabel(r.state)} ${r.msFirstByte} мс"
        val extra = when {
            r.alerts.isNotEmpty() -> r.alerts.joinToString()
            r.state == TlsState.SERVER_HELLO || r.state == TlsState.HANDSHAKE_COMPLETE -> r.negotiated ?: ""
            r.state == TlsState.CONNECT_FAILED -> r.netError.symbol()
            else -> ""
        }
        return if (extra.isBlank()) base else "$base ($extra)"
    }

    private fun isRstInjected(r: netscope.net.TlsReply): Boolean =
        r.state == TlsState.RST && baselineRtt > 0 && r.msFirstByte < baselineRtt * 0.5

    /**
     * SNI-фильтрация проверяется на заведомо «своём» адресе: подставляем
     * подозрительное имя в ClientHello, а адрес оставляем рабочим.
     * Так DNS-фильтрация не мешает и результат однозначен.
     */
    private suspend fun sniBlacklist() {
        val c = ctx.reg.add(Check("dpi.sni", "dpi", "Фильтрация по SNI"))
        c.critical = true
        if (goodIp.isEmpty()) { c.set(Verdict.SKIP, "нет рабочего эталона"); return }
        val names = Targets.load(ctx.opts.extraDomains).suspect.take(if (ctx.opts.mode == Mode.QUICK) 5 else 10)
        val res = parMap(8, names) { n ->
            val r = TlsProbeRaw.exchange(goodIp, 443, TlsWire.build(HelloSpec(sni = n)), 3000, 2200)
            n to r
        }
        val rst = res.filter { it.second.state == TlsState.RST || it.second.state == TlsState.TIMEOUT }
        val injected = res.filter { isRstInjected(it.second) }
        val passed = res.filter { it.second.state == TlsState.SERVER_HELLO || it.second.state == TlsState.HANDSHAKE_COMPLETE }
        when {
            injected.isNotEmpty() -> {
                c.set(Verdict.FAIL, "SNI-фильтрация: ${injected.size} из ${names.size} имён отбрасываются")
                injected.forEach { (n, r) -> c.ev("  $n → ${describe(r)} ← быстреше половины RTT, это не сервер") }
                ctx.blockers.add("SNI-фильтрация: " + injected.joinToString { it.first })
                ctx.sniBlocked = true
            }
            rst.isNotEmpty() -> {
                c.set(Verdict.WARN, "${rst.size} имён не дали ответа (RST/тишина), но без признака инъекции")
                rst.forEach { (n, r) -> c.ev("  $n → ${describe(r)}") }
            }
            else -> c.set(Verdict.OK, "ни одно из ${names.size} имён не отфильтровано — SNI-фильтрации нет")
        }
        passed.forEach { (n, r) -> c.ev("  пропущено: ${n.padEnd(24)} ${describe(r)}") }
        c.ev("метод: ClientHello с проверяемым SNI на адрес ${goodIp} (известен как доступный)")
    }

    private suspend fun rstInjection() {
        val c = ctx.reg.add(Check("dpi.rst", "dpi", "Инъекция TCP RST"))
        if (goodIp.isEmpty() || baselineRtt <= 0) { c.set(Verdict.SKIP, "нет данных"); return }
        val names = Targets.load(ctx.opts.extraDomains).suspect.take(6)
        val trials = 3
        val data = parMap(8, names) { n ->
            val runs = (0 until trials).map {
                TlsProbeRaw.exchange(goodIp, 443, TlsWire.build(HelloSpec(sni = n)), 3000, 1500)
            }
            n to runs
        }
        val killed = data.filter { (_, runs) -> runs.count { it.state == TlsState.RST } >= (trials + 1) / 2 }
        if (killed.isEmpty()) {
            c.set(Verdict.INFO, "стабильных RST-инъекций не обнаружено")
            c.ev("контрольный RTT = $baselineRtt мс, порог подозрения = ${baselineRtt / 2} мс")
            data.take(3).forEach { (n, runs) -> c.ev("$n → " + runs.joinToString(", ") { "${stateLabel(it.state)} ${it.msFirstByte}мс" }) }
            return
        }
        c.set(Verdict.FAIL, "${killed.size} имени(й) стабильно отбрасываются по RST")
        killed.forEach { (n, runs) ->
            val med = runs.map { it.msFirstByte }.sorted()[runs.size / 2]
            c.ev("  $n → RST за $med мс при контрольном RTT $baselineRtt мс (x${"%.2f".format(med.toDouble() / baselineRtt)})")
        }
        c.ev("RST быстрее половины RTT не может прийти от удалённого сервера — его подделало устройство в пути")
        ctx.dpiDetected = true
    }

    /** Какие именно способы маскировки SNI проходят мимо фильтра. */
    private suspend fun obfuscationVariants() {
        val c = ctx.reg.add(Check("dpi.variants", "dpi", "Обфускация SNI: что пролезает"))
        c.critical = true
        if (goodIp.isEmpty()) { c.set(Verdict.SKIP, "нет рабочего эталона"); return }
        val suspects = Targets.load(ctx.opts.extraDomains).suspect.take(12)
        val probe = suspects.firstOrNull { name ->
            runCatching { TlsProbeRaw.exchangeBlocking(goodIp, 443, TlsWire.build(HelloSpec(sni = name)), 3000, 1500).state }
                .getOrNull() == TlsState.RST
        }
            ?: suspects.firstOrNull { name ->
                runCatching { TlsProbeRaw.exchangeBlocking(goodIp, 443, TlsWire.build(HelloSpec(sni = name)), 3000, 1500).blocked }
                    .getOrDefault(false)
            }
        if (probe == null) { c.set(Verdict.INFO, "фильтруемых имён нет — сравнивать нечего"); return }
        c.ev("цель для сравнения: $probe")

        val variants = listOf(
            Variant("обычный SNI") { HelloSpec(sni = probe, label = "обычный") },
            Variant("без SNI") { HelloSpec(sni = null, label = "без SNI") },
            Variant("SNI в заглавных буквах") { HelloSpec(sni = probe.uppercase(), label = "uppercase") },
            Variant("SNI с точкой в конце") { HelloSpec(sni = "$probe.", label = "FQDN с точкой") },
            Variant("SNI в punycode") { HelloSpec(sni = IDN.toASCII(probe), label = "punycode") },
            Variant("SNI в нестандартном расширении") { HelloSpec(sni = probe, sniExtensionId = 0x1234, label = "ext 0x1234") },
            Variant("SNI за 200 байт «подушки»") { HelloSpec(sni = probe, padBeforeSni = 200, label = "padding") },
            Variant("SNI во втором TLS-рекорде") { HelloSpec(sni = probe, firstRecordBytes = 60, label = "2-й record") },
            Variant("с GREASE-значениями") { HelloSpec(sni = probe, grease = true, label = "GREASE") },
            Variant("без ALPN") { HelloSpec(sni = probe, alpn = emptyList(), label = "без ALPN") },
            Variant("только TLS 1.2") { HelloSpec(sni = probe, versions = listOf(0x0303), label = "TLS1.2") },
            Variant("только TLS 1.0") { HelloSpec(sni = probe, versions = listOf(0x0301), label = "TLS1.0") },
            Variant("SNI с NUL-байтом") { HelloSpec(sniBytes = probe.toByteArray() + byteArrayOf(0), label = "NUL") }
        )

        data class Trial(val name: String, val passed: Boolean, val reply: netscope.net.TlsReply)
        val results = parMap(6, variants) { v ->
            val r = TlsProbeRaw.exchange(goodIp, 443, TlsWire.build(v.build()), 3000, 1800)
            Trial(v.name, r.state == TlsState.SERVER_HELLO || r.state == TlsState.HANDSHAKE_COMPLETE, r)
        }
        val passed = results.filter { it.passed }
        val failed = results.filter { !it.passed }
        results.forEach { t -> c.ev(("  " + (if (t.passed) "пролезло " else "отсечено ") + t.name).padEnd(46) + describe(t.reply)) }

        if (passed.size > 1) {
            c.set(Verdict.WARN, "обычный SNI отбрасывается, но ${passed.size} из ${failed.size} вариантов обхода срабатывают")
            c.ev("вывод: фильтр разбирает SNI наивным разбором и обходится маскировкой")
            passed.map { it.name }.forEach { ctx.evidenceAll.add("обход SNI через «$it»") }
            ctx.obfsFeasible = "частично: SNI маскируется ($probe)"
        } else if (failed.isEmpty()) {
            c.set(Verdict.OK, "ни один вариант не отбрасывается — фильтрации $probe нет")
        } else {
            c.set(Verdict.FAIL, "все варианты обфускации отброшены — фильтр разбирает SNI глубоко")
            c.ev("вывод: простая маскировка имени не поможет, нужна обфускация всего потока (obfs4/snowflake)")
        }
    }

    private data class Variant(val name: String, val make: () -> HelloSpec) {
        fun build(): HelloSpec = make()
    }

    private suspend fun fragmentation() {
        val c = ctx.reg.add(Check("dpi.frag", "dpi", "Устойчивость к фрагментации"))
        if (goodIp.isEmpty()) { c.set(Verdict.SKIP, "нет рабочего эталона"); return }
        val spec = HelloSpec(sni = goodIp.let { "example.com" })
        val payload = TlsWire.build(spec)
        val chunk = payload.size / 4
        val r = TlsProbeRaw.exchange(
            goodIp, 443, payload, 3000, 2500,
            splitWrites = listOf(chunk, chunk * 2, chunk * 3), gapMs = 18
        )
        val ok = r.state == TlsState.SERVER_HELLO || r.state == TlsState.HANDSHAKE_COMPLETE
        ctx.fragTolerance = if (ok) "да" else "нет"
        if (ok) {
            c.set(Verdict.OK, "SNI размазан по 4 сегментам с паузами — сервер и middlebox собрали")
            c.ev("значит padding/фрагментация в вашем канале не ломает соединение")
        } else {
            c.set(Verdict.WARN, "разорванный ClientHello не дошёл — middlebox смотрит только в начало пакета")
            c.ev("padding помогает, но рвать рукопожатие на части нельзя")
            ctx.blockers.add("middlebox разбирает только первый пакет")
        }
        c.ev(describe(r))
    }

    private suspend fun tlsInTls() {
        val c = ctx.reg.add(Check("dpi.tlsintls", "dpi", "Вложенный TLS (обкатка obfs4)"))
        c.critical = true
        if (goodIp.isEmpty()) { c.set(Verdict.SKIP, "нет рабочего эталона"); return }
        val outer = TlsWire.build(HelloSpec(sni = goodIp))
        val inner = TlsWire.build(HelloSpec(sni = "obfs4.invalid", alpn = emptyList()))
        val combined = outer + inner
        val r = TlsProbeRaw.exchange(goodIp, 443, combined, 3000, 2500)
        val ok = r.state == TlsState.SERVER_HELLO || r.state == TlsState.HANDSHAKE_COMPLETE
        ctx.tlsInTls = if (ok) "да" else "нет"
        if (ok) {
            c.set(Verdict.OK, "TLS внутри TLS на 443 проходит — obfs4 технически возможен")
            c.ev("middlebox не распознаёт вложенный TLS-рекорд в момент разбора SNI")
            c.ev("остаётся проверить сам мост: обкатка должна идти до конца рукопожатия")
        } else {
            c.set(Verdict.FAIL, "вложенный TLS отбрасывается — обкатка obfs4 на 443 не пройдёт")
            c.ev("(${describe(r)})")
            ctx.blockers.add("TLS-в-TLS не проходит")
        }
        ctx.obfsFeasible = when {
            ok -> ctx.obfsFeasible.takeIf { it != "неизвестно" } ?: "да: TLS-в-TLS принимается"
            else -> "нет: вложенный TLS режется"
        }
    }

    /** Блокировка по адресу, а не по имени: тот же SNI, но соединение напрямую по IP цели. */
    private suspend fun ipLevel() {
        val c = ctx.reg.add(Check("dpi.iplevel", "dpi", "Блокировка по адресу"))
        val t = Targets.load(ctx.opts.extraDomains)
        val domains = t.suspect.take(if (ctx.opts.mode == Mode.QUICK) 4 else 8)
        data class IpTrial(val domain: String, val ip: String?, val reply: netscope.net.TlsReply?)
        val res = parMap(6, domains) { d ->
            val ip = withContext(Dispatchers.IO) { runCatching { java.net.InetAddress.getByName(d).hostAddress }.getOrNull() }
            if (ip == null) IpTrial(d, null, null)
            else {
                val r = TlsProbeRaw.exchange(ip, 443, TlsWire.build(HelloSpec(sni = d)), 3000, 2000)
                IpTrial(d, ip, r)
            }
        }
        val noDns = res.filter { it.ip == null }
        val blocked = res.filter { it.reply != null && it.reply.state in listOf(TlsState.RST, TlsState.TIMEOUT) }
        val alive = res.filter { it.reply != null && (it.reply.state == TlsState.SERVER_HELLO || it.reply.state == TlsState.HANDSHAKE_COMPLETE) }
        when {
            noDns.size > 0 -> c.ev("${noDns.size} домен(ов) не резолвятся: ${noDns.joinToString { it.domain }} — DNS-уровень блокировки")
            blocked.isNotEmpty() -> {
                c.set(Verdict.FAIL, "${blocked.size} адресов не отвечают на 443 — блокировка по IP")
                blocked.forEach { t -> t.reply?.let { c.ev("  ${t.domain} (${t.ip}) -> ${describe(it)}") } }
                ctx.blockers.add("блокировка по IP-адресу")
            }
            else -> {
                c.set(Verdict.OK, "адреса отвечают — блокировки по IP нет")
                alive.forEach { t -> t.reply?.let { c.ev("  ${t.domain} (${t.ip}) -> ${describe(it)}") } }
            }
        }
        if (noDns.size > 0 && blocked.isEmpty()) c.set(Verdict.WARN, "домены не резолвятся, но адреса отвечают — фильтр только на DNS")
    }
}
