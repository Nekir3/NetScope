package netscope.report

import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Verdict
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

object Html {
    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    fun render(ctx: Ctx, started: Instant, finished: Instant): String {
        val checks = ctx.reg.checks
        val fails = checks.count { it.verdict == Verdict.FAIL }
        val warns = checks.count { it.verdict == Verdict.WARN }
        val dur = Duration.between(started, finished).seconds
        val verdictClass = if (fails > 0) "fail" else if (warns > 0) "warn" else "ok"
        val verdictText = if (fails > 0) "Среда модифицирована" else if (warns > 0) "Есть замечания" else "Признаков фильтрации нет"

        val sb = StringBuilder()
        sb.append("""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScope — отчёт ${esc(DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm").withZone(ZoneId.systemDefault()).format(finished))}</title>
<style>
:root{--bg:#0b0f16;--panel:#121826;--panel2:#0e1420;--line:#1e2a3d;--fg:#dce4f0;--dim:#7c8ba3;--ok:#4ade80;--warn:#fbbf24;--fail:#f87171;--info:#38bdf8;--acc:#8b5cf6}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 20% -10%,#16203a 0%,var(--bg) 55%);color:var(--fg);
font:14px/1.6 ui-sans-serif,system-ui,"Segoe UI",Roboto,Inter,Arial,sans-serif;padding:32px 20px}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.02em}
h1 span{background:linear-gradient(90deg,#8b5cf6,#38bdf8);-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{color:var(--dim);margin-bottom:24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin-bottom:16px}
.verdict{display:flex;align-items:center;gap:14px;font-size:20px;font-weight:650}
.dot{width:12px;height:12px;border-radius:50%;flex:none}
.ok .dot{background:var(--ok);box-shadow:0 0 0 6px #4ade8022}
.warn .dot{background:var(--warn);box-shadow:0 0 0 6px #fbbf2422}
.fail .dot{background:var(--fail);box-shadow:0 0 0 6px #f8717122}
.ok .t{color:var(--ok)}.warn .t{color:var(--warn)}.fail .t{color:var(--fail)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:16px}
.kv{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.kv b{display:block;color:var(--dim);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.kv span{font-size:15px;word-break:break-word}
section{margin-bottom:18px}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.1em;color:var(--dim);margin:0 0 10px;font-weight:600}
.chk{border:1px solid var(--line);border-radius:10px;padding:11px 13px;margin-bottom:8px;background:var(--panel2)}
.chk.fail{border-color:#f8717155}.chk.warn{border-color:#fbbf2455}
.chk .h{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.chk .m{font-weight:600}
.chk .d{color:var(--dim);flex:1 1 100%;margin-top:3px}
.chk.fail .m{color:var(--fail)}.chk.warn .m{color:var(--warn)}.chk.ok .m{color:var(--ok)}.chk.info .m{color:var(--info)}
.pill{font-size:11px;padding:1px 8px;border-radius:99px;border:1px solid var(--line);color:var(--dim);white-space:nowrap}
.ev{margin:8px 0 0;padding:0;list-style:none;font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#93a3ba}
.ev li{padding:1px 0 1px 14px;position:relative}
.ev li:before{content:"›";position:absolute;left:0;color:var(--acc)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
tr:last-child td{border-bottom:none}
.tag{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;border:1px solid}
.tag.ok{color:var(--ok);border-color:#4ade8055;background:#4ade8011}
.tag.warn{color:var(--warn);border-color:#fbbf2455;background:#fbbf2411}
.tag.fail{color:var(--fail);border-color:#f8717155;background:#f8717111}
.tag.neutral{color:var(--dim);border-color:var(--line)}
footer{color:var(--dim);font-size:12.5px;margin-top:22px;border-top:1px solid var(--line);padding-top:14px}
@media (prefers-color-scheme:light){body{background:#f6f8fc;color:#16202f}body .card,.kv,.chk{background:#fff;border-color:#e2e8f0}
.kv b{color:#64748b}.chk .d{color:#64748b}.ev{color:#475569}h1 span{background:linear-gradient(90deg,#7c3aed,#0284c7);-webkit-background-clip:text;background-clip:text}
footer{color:#64748b;border-color:#e2e8f0}}
</style></head><body><div class="wrap">
""")

        sb.append("<h1><span>NetScope</span> · отчёт сетевого сканирования</h1>")
        sb.append("<div class=\"sub\">${esc(fmt().format(started))} — ${esc(fmt().format(finished))} · ${dur} с · режим: ${esc(ctx.opts.mode.title)} · ${esc(ctx.hostName)}</div>")

        sb.append("<div class=\"card verdict $verdictClass\"><span class=\"dot\"></span><span class=\"t\">$verdictText</span>")
        sb.append("<span class=\"pill\">${checks.size} проверок</span>")
        sb.append("<span class=\"pill\" style=\"color:var(--ok)\">${checks.count { it.verdict == Verdict.OK }} ок</span>")
        sb.append("<span class=\"pill\" style=\"color:var(--warn)\">$warns вним.</span>")
        sb.append("<span class=\"pill\" style=\"color:var(--fail)\">$fails блок</span></div>")

        sb.append("<div class=\"card\"><div class=\"grid\">")
        fun kv(k: String, v: String) { if (v.isNotBlank()) sb.append("<div class=\"kv\"><b>$k</b><span>${esc(v)}</span></div>") }
        kv("Внешний IPv4", ctx.publicIpV4)
        kv("Внешний IPv6", ctx.publicIpV6)
        kv("Гео", listOf(ctx.geoCountry, ctx.geoCity).filter { it.isNotBlank() }.joinToString(", "))
        kv("Оператор", ctx.geoOrg)
        kv("Резолверы", ctx.systemResolvers.joinToString(", "))
        kv("Path MTU", if (ctx.pathMtu > 0) "${ctx.pathMtu} байт" else "")
        kv("Базовый RTT", if (ctx.rttBaseline > 0) "${ctx.rttBaseline} мс" else "")
        kv("Часовой пояс", ctx.systemTz)
        sb.append("</div></div>")

        sb.append("<div class=\"card\"><h2>Обходные транспорты</h2><table>")
        fun tr(name: String, state: String) {
            val good = state.startsWith("да") || state.contains("возможно")
            val bad = state.startsWith("нет")
            val cls = if (good) "ok" else if (bad) "fail" else "warn"
            sb.append("<tr><td>${esc(name)}</td><td><span class=\"tag $cls\">${esc(state)}</span></td></tr>")
        }
        tr("obfs4 (обкатка TLS-в-TLS)", ctx.obfsFeasible)
        tr("snowflake (WebRTC / UDP)", ctx.snowflakeFeasible)
        tr("meek (domain fronting)", ctx.meekFeasible)
        tr("Устойчивость к фрагментации", ctx.fragTolerance)
        tr("Фильтрация по SNI", if (ctx.sniBlocked) "да — имя видно и фильтруется" else "не обнаружена")
        sb.append("</table></div>")

        if (ctx.blockers.isNotEmpty()) {
            sb.append("<div class=\"card\"><h2>Обнаруженные признаки вмешательства</h2><ul class=\"ev\">")
            ctx.blockers.distinct().forEach { sb.append("<li>${esc(it)}</li>") }
            sb.append("</ul></div>")
        }

        val groups = checks.groupBy { it.section }
        for (sec in netscope.probe.SECTIONS) {
            val list = groups[sec.id] ?: continue
            sb.append("<section><h2>${esc(sec.title)} <span style=\"text-transform:none\">— ${esc(sec.hint)}</span></h2>")
            list.forEach { ch -> sb.append(checkHtml(ch)) }
            sb.append("</section>")
        }

        sb.append("<footer>NetScope измеряет только технические признаки вмешательства в ваш трафик и не делает выводов о его причинах. ")
        sb.append("Отчёт можно приложить к баг-репорту или к заявке оператору связи. ")
        sb.append("Глубокий разбор пакетов: <code>netsh trace start capture=yes tracefile=netscope.etl</code></footer>")
        sb.append("</div></body></html>")
        return sb.toString()
    }

    private fun checkHtml(c: Check): String {
        val cls = when (c.verdict) {
            Verdict.OK -> "ok"; Verdict.WARN -> "warn"; Verdict.FAIL -> "fail"
            Verdict.INFO -> "info"; Verdict.SKIP -> ""; Verdict.RUN -> ""
        }
        val sb = StringBuilder()
        sb.append("<div class=\"chk ${if (cls == "info") "" else cls}\">")
        sb.append("<div class=\"h\"><span class=\"m\">${esc(c.title)}</span>")
        sb.append("<span class=\"pill\">${esc(c.verdict.label)}</span>")
        if (c.durationMs > 0) sb.append("<span class=\"pill\">${c.durationMs} мс</span>")
        sb.append("</div>")
        if (c.detail.isNotBlank()) sb.append("<div class=\"d\">${esc(c.detail)}</div>")
        if (c.evidence.isNotEmpty()) {
            sb.append("<ul class=\"ev\">")
            c.evidence.forEach { sb.append("<li>${esc(it)}</li>") }
            sb.append("</ul>")
        }
        sb.append("</div>")
        return sb.toString()
    }

    private fun fmt() = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss").withZone(ZoneId.systemDefault())
}
