package netscope.ui

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Level
import netscope.core.LogLine
import netscope.core.Registry
import netscope.core.Verdict
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Живой интерфейс: перерисовывает экран целиком, снизу — поток логов.
 * Если терминал не умеет ANSI или вывод перенаправлен — печатает построчно.
 */
class Live(private val ctx: Ctx, private val term: Terminal, private val head: Headline) {
    private val dash = Dashboard(ctx.reg, netscope.probe.SECTIONS, "NetScope", "1.0.0")
    private val logs = ArrayDeque<LogLine>(900)
    private val fmt = DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault())
    private var painter: Job? = null
    val rich: Boolean = term.virtualTerminal && !ctx.opts.noLive
    val allLogs: List<LogLine> get() = logs.toList()

    fun start(scope: CoroutineScope) {
        if (rich) term.enterLive()
        scope.launch(Dispatchers.IO) {
            val announced = HashSet<String>()
            val resolved = HashSet<String>()
            while (isActive) {
                val batch = ArrayList<LogLine>(64)
                while (batch.size < 256) {
                    val l = ctx.reg.log.tryReceive().getOrNull() ?: break
                    batch.add(l)
                }
                for (l in batch) {
                    logs.addLast(l)
                    while (logs.size > 900) logs.removeFirst()
                    if (!rich) plain(l)
                }
                for (ch in ctx.reg.checks) {
                    if (announced.add(ch.id) && ch.verdict == Verdict.RUN && !rich) {
                        plainLine(Level.INFO, "section", "${Glyph.arrow()} ${ch.title}")
                    }
                    if (ch.verdict != Verdict.RUN && resolved.add(ch.id)) {
                        ch.durationMs = ch.elapsedMs()
                        if (!rich) plainLine(levelOf(ch), "check", "${markOf(ch)} ${ch.title} ${Glyph.arrow()} ${ch.detail}")
                    }
                }
                delay(45)
            }
        }
        if (rich) {
            painter = scope.launch {
                while (isActive) {
                    dash.tick()
                    val (cols, rows) = term.size()
                    if (dash.changed(head, logs.toList(), cols, rows)) {
                        term.write(Ansi.HOME + dash.lastRendered)
                    }
                    delay(110)
                }
            }
        }
    }

    fun stop() {
        painter?.cancel()
        if (rich) term.exitLive()
    }

    private fun levelOf(ch: Check) = when (ch.verdict) {
        Verdict.FAIL -> Level.FAIL
        Verdict.WARN -> Level.WARN
        Verdict.OK -> Level.OK
        else -> Level.INFO
    }

    private fun markOf(ch: Check) = when (ch.verdict) {
        Verdict.FAIL -> Glyph.fail()
        Verdict.WARN -> Glyph.warn()
        Verdict.OK -> Glyph.ok()
        else -> Glyph.dotEmpty()
    }

    private fun plain(l: LogLine) {
        val t = Ansi.gray(fmt.format(l.at))
        val lv = when (l.level) {
            Level.OK -> Ansi.green(Glyph.ok()); Level.FAIL -> Ansi.red(Glyph.fail())
            Level.WARN -> Ansi.yellow(Glyph.warn()); Level.INFO -> Ansi.blue(Glyph.arrow())
            Level.CRIT -> Ansi.magenta(Glyph.fail()); else -> Ansi.gray(Glyph.dotEmpty())
        }
        term.write("$t $lv ${Ansi.cyan(Ansi.fit(l.source, 12))} ${Ansi.gray(l.text)}\r\n")
    }

    private fun plainLine(level: Level, source: String, text: String) {
        val lv = when (level) {
            Level.OK -> Ansi.green(Glyph.ok()); Level.FAIL -> Ansi.red(Glyph.fail())
            Level.WARN -> Ansi.yellow(Glyph.warn()); else -> Ansi.blue(Glyph.arrow())
        }
        term.write("${Ansi.gray(fmt.format(java.time.Instant.now()))} $lv ${Ansi.cyan(Ansi.fit(source, 12))} $text\r\n")
    }
}
