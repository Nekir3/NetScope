package netscope

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Level
import netscope.core.Mode
import netscope.core.Options
import netscope.core.Registry
import netscope.core.Targets
import netscope.core.Verdict
import netscope.probe.BridgeProbe
import netscope.probe.DnsProbe
import netscope.probe.DpiProbe
import netscope.probe.EnvProbe
import netscope.probe.GeoProbe
import netscope.probe.HttpProbe
import netscope.probe.LeakProbe
import netscope.probe.MitmProbe
import netscope.probe.SECTIONS
import netscope.probe.TcpProbe
import netscope.probe.TlsProbe
import netscope.report.Html
import netscope.report.Report
import netscope.ui.Ansi
import netscope.ui.Glyph
import netscope.ui.Headline
import netscope.ui.Live
import netscope.ui.Terminal
import java.io.File
import java.time.Instant

const val VERSION = "1.0.0"

fun main(args: Array<String>) {
    val opts = parseArgs(args)
    val term = Terminal()
    Ansi.enabled = !opts.noColor && System.getenv("NO_COLOR").isNullOrEmpty()
    Glyph.ascii = opts.ascii

    if (opts.help) { printHelp(term); return }
    if (opts.version) { println("NetScope $VERSION"); return }
    if (!term.enableAnsi()) Ansi.enabled = false

    if (opts.listDomains) { listDomains(term); return }

    val reg = Registry()
    val head = Headline(profile = "локальный", mode = opts.mode.title, targets = Targets.load(opts.extraDomains).let { it.control.size + it.suspect.size })
    val ctx = Ctx(opts, reg, head)
    val live = Live(ctx, term, head)

    printBanner(term, opts)
    val started = Instant.now()
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    live.start(scope)
    val t0 = System.currentTimeMillis()

    runBlocking {
        val wanted = if (opts.sections.isEmpty()) SECTIONS.map { it.id }.toSet() else opts.sections
        for (sec in SECTIONS) {
            if (sec.id !in wanted) continue
            head.profile = sec.id
            reg.emit(Level.INFO, "run", "${Glyph.arrow()} секция «${sec.title}» ${Glyph.arrow()} ${sec.hint}")
            val before = reg.checks.size
            val st = System.currentTimeMillis()
            try {
                when (sec.id) {
                    "env" -> EnvProbe(ctx).run()
                    "dns" -> DnsProbe(ctx).run()
                    "tcp" -> TcpProbe(ctx).run()
                    "http" -> HttpProbe(ctx).run()
                    "tls" -> TlsProbe(ctx).run()
                    "dpi" -> DpiProbe(ctx).run()
                    "mitm" -> MitmProbe(ctx).run()
                    "leaks" -> LeakProbe(ctx).run()
                    "geo" -> GeoProbe(ctx).run()
                    "bridges" -> BridgeProbe(ctx).run()
                }
            } catch (e: Throwable) {
                reg.fail("run", "секция «${sec.title}» упала: ${e.message ?: e::class.java.simpleName}")
                if (opts.verbose) e.printStackTrace()
            }
            val took = System.currentTimeMillis() - st
            val new = reg.checks.drop(before)
            val bad = new.count { it.verdict == Verdict.FAIL }
            val warn = new.count { it.verdict == Verdict.WARN }
            reg.emit(
                when {
                    bad > 0 -> Level.FAIL
                    warn > 0 -> Level.WARN
                    else -> Level.OK
                },
                "run",
                "«${sec.title}» за ${"%.1f".format(took / 1000.0)} с " + Glyph.arrow() + " ${new.size} проверок" +
                        (if (bad > 0) ", $bad с признаками вмешательства" else if (warn > 0) ", $warn замечаний" else ", чисто")
            )
        }
    }

    val total = System.currentTimeMillis() - t0
    head.elapsed = total
    Thread.sleep(500)
    live.stop()
    scope.cancel()
    val finished = Instant.now()

    val width = term.size().first
    val logs = live.allLogs
    term.write("\r\n")
    term.write(Report.console(ctx, started, finished, width))
    if (Ansi.enabled) term.write("\r\n")

    opts.jsonOut?.let { writeFile(it, Report.json(ctx, started, finished, logs)) }
    opts.htmlOut?.let { writeFile(it, Html.render(ctx, started, finished)) }
    if (opts.jsonOut != null || opts.htmlOut != null) {
        term.write("  " + Ansi.gray("отчёты: ") + listOfNotNull(opts.jsonOut, opts.htmlOut).joinToString(", ") + "\r\n\r\n")
    }

    val fails = reg.checks.count { it.verdict == Verdict.FAIL }
    val warns = reg.checks.count { it.verdict == Verdict.WARN }
    val critical = reg.checks.any { it.critical && it.verdict == Verdict.FAIL }
    System.exit(when {
        critical -> 2
        fails > 0 -> 1
        warns > 0 -> 1
        else -> 0
    })
}

private fun writeFile(path: String, content: String) {
    runCatching {
        val f = File(path)
        f.absoluteFile.parentFile?.mkdirs()
        f.writeText(content, Charsets.UTF_8)
    }
}

private fun printBanner(term: Terminal, opts: Options) {
    val w = term.size().first
    val title = "N E T S C O P E"
    val sub = "диагностика фильтрации сети " + Glyph.bullet() + " DPI " + Glyph.bullet() + " цензура " + Glyph.bullet() +
            " утечки " + Glyph.bullet() + " обфускация"
    term.write("\r\n")
    term.write("  " + Ansi.bold(Ansi.gradient(title)) + Ansi.gray("  v$VERSION") + "\r\n")
    term.write("  " + Ansi.gray(sub) + "\r\n")
    term.write("  " + Ansi.gray(Glyph.sep().repeat((w - 4).coerceIn(20, 110))) + "\r\n")
    term.write("  " + Ansi.gray("Ctrl+C — прервать; отчёт в конце прогона") + "\r\n")
    term.write("\r\n")
}

private fun listDomains(term: Terminal) {
    val t = Targets.load()
    term.write("\r\n")
    fun block(title: String, list: List<String>) {
        term.write("  " + Ansi.bold(title) + Ansi.gray("  (${list.size})") + "\r\n")
        list.chunked(3).forEach { row ->
            term.write("    " + row.joinToString("  ") { Ansi.silver(Ansi.fit(it, 26)) } + "\r\n")
        }
        term.write("\r\n")
    }
    block("Контрольные (эталоны)", t.control)
    block("Проверяемые на блокировку", t.suspect)
    block("Определение внешнего IP", t.egress)
    block("CDN для fronting", t.fronting)
    term.write("  " + Ansi.gray("Списки берутся из src/main/resources/netscope/domains.txt — правьте под свою сеть.") + "\r\n\r\n")
}

private fun printHelp(term: Terminal) {
    val sb = StringBuilder()
    fun l(s: String) { sb.append(s).append("\r\n") }
    l("")
    l("  ${Ansi.bold(Ansi.gradient("NetScope $VERSION"))} ${Ansi.gray("— измеряет, что происходит с вашим трафиком")}")
    l("")
    l("  ${Ansi.bold("Использование:")}  netscope [опции]")
    l("")
    l("  ${Ansi.bold("Секции")} ${Ansi.gray("(по умолчанию все, по порядку):")}")
    SECTIONS.forEach { l("    ${Ansi.silver(Ansi.fit(it.id, 10))} ${Ansi.gray(it.title + " — " + it.hint)}") }
    l("")
    l("  ${Ansi.bold("Опции:")}")
    l("    ${Ansi.silver("--mode quick|standard|deep")}  глубина прогона (по умолчанию standard)")
    l("    ${Ansi.silver("--section id,id")}          прогнать только эти секции")
    l("    ${Ansi.silver("--domain пример.рф")}       добавить домен в проверку (можно несколько раз)")
    l("    ${Ansi.silver("--bridges \"строка\"")}      мост Tor для проверки (можно несколько раз)")
    l("    ${Ansi.silver("--fetch-bridges")}          взять мосты с bridges.torproject.org")
    l("    ${Ansi.silver("--json out.json")}          выгрузить полный отчёт в JSON")
    l("    ${Ansi.silver("--html out.html")}          выгрузить отчёт-страницу в HTML")
    l("    ${Ansi.silver("--timeout мс")}              таймаут соединений (по умолчанию 4000)")
    l("    ${Ansi.silver("--plain")}                  без live-интерфейса, логи построчно")
    l("    ${Ansi.silver("--no-color | --ascii")}      без цвета / без Unicode-символов")
    l("    ${Ansi.silver("--verbose")}                показать все детали в итоговом отчёте")
    l("    ${Ansi.silver("--list-domains")}            показать используемые списки и выйти")
    l("    ${Ansi.silver("-h, --help | -v, --version")}")
    l("")
    l("  ${Ansi.bold("Примеры:")}")
    l("    ${Ansi.gray("netscope --mode quick")}")
    l("    ${Ansi.gray("netscope --section dns,dpi --domain example.org")}")
    l("    ${Ansi.gray("netscope --html report.html --json report.json --verbose")}")
    l("    ${Ansi.gray("netscope --bridges \"obfs4 1.2.3.4:443 ABCDEF... cert=...\"")}")
    l("")
    l("  ${Ansi.gray("Код возврата: 0 — чисто, 1 — есть замечания, 2 — подтверждённое вмешательство.")}")
    l("")
    term.write(sb.toString())
}

private fun parseArgs(args: Array<String>): Options {
    var mode: String? = null
    val sections = mutableSetOf<String>()
    val domains = mutableListOf<String>()
    val bridges = mutableListOf<String>()
    var fetch = false
    var timeout = 4000
    var json: String? = null
    var html: String? = null
    var noColor = false
    var ascii = false
    var verbose = false
    var plain = false
    var listDomains = false
    var help = false
    var version = false

    var i = 0
    while (i < args.size) {
        val a = args[i]
        fun next(): String = args.getOrNull(++i) ?: ""
        when {
            a == "-h" || a == "--help" || a == "/?" -> help = true
            a == "-v" || a == "--version" -> version = true
            a == "--mode" -> mode = next()
            a.startsWith("--mode=") -> mode = a.substring(7)
            a == "--section" || a == "-s" -> sections += next().split(',').map { it.trim() }.filter { it.isNotEmpty() }
            a.startsWith("--section=") -> sections += a.substring(10).split(',').map { it.trim() }
            a == "--domain" || a == "-d" -> domains += next()
            a.startsWith("--domain=") -> domains += a.substring(9)
            a == "--bridges" || a == "-b" -> bridges += next()
            a.startsWith("--bridges=") -> bridges += a.substring(10)
            a == "--fetch-bridges" -> fetch = true
            a == "--json" -> json = next()
            a.startsWith("--json=") -> json = a.substring(7)
            a == "--html" -> html = next()
            a.startsWith("--html=") -> html = a.substring(7)
            a == "--timeout" -> timeout = next().toIntOrNull() ?: 4000
            a.startsWith("--timeout=") -> timeout = a.substring(10).toIntOrNull() ?: 4000
            a == "--no-color" || a == "--nocolor" -> noColor = true
            a == "--ascii" -> ascii = true
            a == "--verbose" -> verbose = true
            a == "--plain" || a == "--no-live" -> plain = true
            a == "--list-domains" -> listDomains = true
            else -> {
                System.err.println("Неизвестный аргумент: $a  (--help — список опций)")
            }
        }
        i++
    }
    return Options(
        mode = Mode.parse(mode),
        sections = sections,
        extraDomains = domains,
        bridges = bridges,
        fetchBridges = fetch,
        timeoutMs = timeout,
        jsonOut = json,
        htmlOut = html,
        noColor = noColor,
        ascii = ascii,
        verbose = verbose,
        noLive = plain,
        listDomains = listDomains,
        help = help,
        version = version
    )
}
