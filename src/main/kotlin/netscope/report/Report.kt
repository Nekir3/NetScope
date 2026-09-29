package netscope.report

import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Json
import netscope.core.Level
import netscope.core.LogLine
import netscope.core.Verdict
import netscope.ui.Ansi
import netscope.ui.Glyph
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

object Report {

    fun json(ctx: Ctx, started: Instant, finished: Instant, logs: List<LogLine>): String {
        val checks = ctx.reg.checks
        val bySection = LinkedHashMap<String, List<Check>>()
        checks.forEach { bySection.getOrPut(it.section) { emptyList() }.let { } }
        val sections = Json.Obj(
            bySection.keys.mapIndexed { i, id ->
                id to Json.Arr(bySection[id]?.map { it.toJson() } ?: emptyList())
            }.toMap()
        )
        val root = Json.Obj(
            mapOf(
                "tool" to Json.Str("NetScope"),
                "version" to Json.Str("1.0.0"),
                "started" to Json.Str(started.toString()),
                "finished" to Json.Str(finished.toString()),
                "duration_s" to Json.Num(Duration.between(started, finished).toMillis() / 1000.0),
                "mode" to Json.Str(ctx.opts.mode.id),
                "summary" to Json.Obj(mapOf(
                    "total" to Json.Num(checks.size.toDouble()),
                    "ok" to Json.Num(checks.count { it.verdict == Verdict.OK }.toDouble()),
                    "info" to Json.Num(checks.count { it.verdict == Verdict.INFO }.toDouble()),
                    "warn" to Json.Num(checks.count { it.verdict == Verdict.WARN }.toDouble()),
                    "fail" to Json.Num(checks.count { it.verdict == Verdict.FAIL }.toDouble()),
                    "skip" to Json.Num(checks.count { it.verdict == Verdict.SKIP }.toDouble()),
                    "verdict" to Json.Str(Verdict.worstOf(checks.map { it.verdict }).name)
                )),
                "network" to Json.Obj(mapOf(
                    "hostname" to Json.Str(ctx.hostName),
                    "timezone" to Json.Str(ctx.systemTz),
                    "public_ipv4" to Json.Str(ctx.publicIpV4),
                    "public_ipv6" to Json.Str(ctx.publicIpV6),
                    "country" to Json.Str(ctx.geoCountry),
                    "country_code" to Json.Str(ctx.geoCountryCode),
                    "city" to Json.Str(ctx.geoCity),
                    "org" to Json.Str(ctx.geoOrg),
                    "isp" to Json.Str(ctx.geoIsp),
                    "resolvers" to Json.Arr(ctx.systemResolvers.map { Json.Str(it) }),
                    "path_mtu" to Json.Num(ctx.pathMtu.toDouble()),
                    "rtt_baseline_ms" to Json.Num(ctx.rttBaseline.toDouble())
                )),
                "obfuscation" to Json.Obj(mapOf(
                    "dpi_detected" to Json.Bool(ctx.dpiDetected),
                    "sni_blocked" to Json.Str(if (ctx.sniBlocked) "да" else "нет"),
                    "tls_in_tls" to Json.Str(ctx.tlsInTls),
                    "fragmentation_tolerance" to Json.Str(ctx.fragTolerance),
                    "obfs4" to Json.Str(ctx.obfsFeasible),
                    "snowflake" to Json.Str(ctx.snowflakeFeasible),
                    "meek" to Json.Str(ctx.meekFeasible)
                )),
                "blockers" to Json.Arr(ctx.blockers.distinct().map { Json.Str(it) }),
                "sections" to sections,
                "log" to Json.Arr(logs.map {
                    Json.Obj(mapOf(
                        "t" to Json.Str(DateTimeFormatter.ISO_INSTANT.format(it.at)),
                        "level" to Json.Str(it.level.name),
                        "src" to Json.Str(it.source),
                        "msg" to Json.Str(it.text)
                    ))
                })
            )
        )
        return root.render(2)
    }

    fun console(ctx: Ctx, started: Instant, finished: Instant, width: Int): String {
        val w = width.coerceIn(70, 160)
        val out = StringBuilder()
        val checks = ctx.reg.checks
        val worst = Verdict.worstOf(checks.map { it.verdict })
        val fails = checks.count { it.verdict == Verdict.FAIL }
        val warns = checks.count { it.verdict == Verdict.WARN }
        val secs = Duration.between(started, finished).seconds

        fun rule(ch: String = Glyph.sep()) = Ansi.gray(ch.repeat(w - 2))

        val stamp = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm").withZone(ZoneId.systemDefault()).format(finished)

        out.append('\n').append(Ansi.gray(Glyph.tl() + Glyph.sep().repeat(w - 2) + Glyph.tr())).append('\n')
        out.append(Ansi.bold(Ansi.gradient("  ИТОГ ПРОГОНА"))).append(Ansi.gray("   " + stamp)).append('\n')
        out.append(Ansi.gray(Glyph.bl() + Glyph.sep().repeat(w - 2) + Glyph.br())).append("\n\n")

        val headline = when {
            fails > 0 -> Ansi.bold(Ansi.red("СРЕДА МОДИФИЦИРОВАНА — есть признаки вмешательства"))
            warns > 0 -> Ansi.bold(Ansi.yellow("ЕСТЬ ЗАМЕЧАНИЯ — вмешательство не доказано"))
            else -> Ansi.bold(Ansi.green("ПРИЗНАКОВ ФИЛЬТРАЦИИ НЕ ОБНАРУЖЕНО"))
        }
        out.append("  ").append(headline).append('\n')
        out.append("  ").append(Ansi.gray("проверок: ")).append(checks.size.toString())
            .append(Ansi.gray("   время: ")).append("$secs с").append('\n')
        out.append("  ").append(Ansi.green("● " + checks.count { it.verdict == Verdict.OK } + " ок"))
            .append(Ansi.gray("   ●")).append(Ansi.cyan(" " + checks.count { it.verdict == Verdict.INFO } + " инфо"))
            .append(Ansi.gray("   ●")).append(Ansi.yellow(" $warns вним."))
            .append(Ansi.gray("   ●")).append(Ansi.red(" $fails блок")).append("\n\n")

        // сеть
        out.append("  ").append(Ansi.bold(Ansi.gray("СЕТЬ"))).append('\n')
        fun kv(k: String, v: String) {
            if (v.isBlank()) return
            out.append("    ").append(Ansi.gray(k.padEnd(16))).append(Ansi.silver(v)).append('\n')
        }
        kv("хост", ctx.hostName)
        kv("внешний IPv4", ctx.publicIpV4)
        kv("внешний IPv6", ctx.publicIpV6)
        kv("гео", listOf(ctx.geoCountry, ctx.geoCity).filter { it.isNotBlank() }.joinToString(", "))
        kv("оператор", ctx.geoOrg)
        kv("резолверы", ctx.systemResolvers.joinToString(", "))
        kv("path MTU", if (ctx.pathMtu > 0) "${ctx.pathMtu} байт" else "")
        kv("RTT", if (ctx.rttBaseline > 0) "$ctx.rttBaseline мс" else "")
        kv("часовой пояс", ctx.systemTz)
        out.append('\n')

        // таблица
        out.append("  ").append(Ansi.bold(Ansi.gray("СЕКЦИЯ".padEnd(20) + "  " + "СТАТУС".padEnd(11) + "  " + "РЕЗУЛЬТАТ"))).append('\n')
        out.append("  ").append(rule()).append('\n')
        val groups = checks.groupBy { it.section }
        val titles = netscope.probe.SECTIONS.map { it.id to it.title }.toMap()
        for ((sid, title) in netscope.probe.SECTIONS) {
            val list = groups[sid] ?: continue
            val v = Verdict.worstOf(list.map { it.verdict })
            out.append("  ").append(Ansi.style(v.style, v.mark))
                .append(' ').append(title.padEnd(19))
                .append(Ansi.style(v.style, v.label.padEnd(11)))
                .append("  ").append(Ansi.gray("${list.count { it.verdict != Verdict.SKIP }} пров."))
                .append('\n')
            for (ch in list) {
                out.append("      ").append(Ansi.gray(Glyph.dotEmpty())).append(' ')
                    .append(Ansi.style(ch.verdict.style, ch.verdict.mark)).append(' ')
                    .append(ch.title.padEnd(34))
                    .append(Ansi.style(ch.verdict.style, Ansi.cut(ch.detail, (w - 56).coerceAtLeast(20))))
                if (ch.durationMs > 0) out.append(Ansi.gray("  ${ch.durationMs}мс"))
                out.append('\n')
            }
        }
        out.append('\n')

        // вмешательство
        val blockers = ctx.blockers.distinct()
        if (blockers.isNotEmpty()) {
            out.append("  ").append(Ansi.bold(Ansi.red("ЧТО ЗАМЕЧЕНО"))).append('\n')
            blockers.forEach { out.append("    ").append(Ansi.red(Glyph.bullet())).append(' ').append(Ansi.silver(it)).append('\n') }
            out.append('\n')
        }

        // обфускация
        out.append("  ").append(Ansi.bold(Ansi.gray("ОБХОДНЫЕ ТРАНСПОРТЫ"))).append('\n')
        fun trow(name: String, state: String) {
            val good = state.startsWith("да") || state.contains("возможно")
            val bad = state.startsWith("нет")
            val col: (String) -> String = when {
                good -> Ansi::green
                bad -> Ansi::red
                else -> Ansi::yellow
            }
            out.append("    ").append(col(if (good) Glyph.ok() else if (bad) Glyph.fail() else Glyph.warn()))
                .append(' ').append(Ansi.silver(Ansi.fit(name, 30)))
                .append(col(state)).append('\n')
        }
        trow("obfs4 (TLS-в-TLS)", ctx.obfsFeasible)
        trow("snowflake (WebRTC/UDP)", ctx.snowflakeFeasible)
        trow("meek (domain fronting)", ctx.meekFeasible)
        trow("устойчивость к фрагментации", ctx.fragTolerance)
        trow("фильтрация по SNI", if (ctx.sniBlocked) "да — имя видно и фильтруется" else "не обнаружена")
        out.append('\n')

        // детали
        val interesting = checks.filter { it.verdict == Verdict.FAIL || it.verdict == Verdict.WARN || (ctx.opts.verbose && it.verdict == Verdict.INFO) }
        if (interesting.isNotEmpty()) {
            out.append("  ").append(Ansi.bold(Ansi.gray("ПОДРОБНО"))).append('\n')
            interesting.forEach { ch ->
                out.append("    ").append(Ansi.style(ch.verdict.style, ch.verdict.mark)).append(' ')
                    .append(Ansi.bold(ch.title)).append(" ").append(Ansi.gray("[${sections(ch.section)}]")).append('\n')
                out.append("      ").append(Ansi.style(ch.verdict.style, ch.detail)).append('\n')
                ch.evidence.take(if (ctx.opts.verbose) 30 else 8).forEach { out.append("      ").append(Ansi.gray(Glyph.bullet() + " " + it)).append('\n') }
                out.append('\n')
            }
        }

        out.append("  ").append(rule()).append('\n')
        out.append("  ").append(Ansi.gray("Проверка измеряет только то, что происходит с вашим трафиком. "))
        out.append(Ansi.gray("Кто и зачем это делает — вне области измерений.")).append('\n')
        out.append("  ").append(Ansi.gray("Для разбора пакетов: netsh trace start capture=yes tracefile=netscope.etl")).append('\n')
        out.append('\n')
        return out.toString()
    }

    private fun sections(id: String) = netscope.probe.SECTIONS.firstOrNull { it.id == id }?.title ?: id
}
