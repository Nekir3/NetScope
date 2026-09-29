package netscope.ui

import netscope.core.Check
import netscope.core.Level
import netscope.core.LogLine
import netscope.core.Registry
import netscope.core.Section
import netscope.core.Verdict
import java.time.ZoneId
import java.time.format.DateTimeFormatter

data class Headline(
    var profile: String = "auto",
    val mode: String = "полный",
    var targets: Int = 0,
    var elapsed: Long = 0,
    var publicIp: String = "—",
    var publicIpNote: String = "",
    var resolver: String = "—",
    var transports: String = ""
) {
    fun sameAs(o: Headline) =
        profile == o.profile && mode == o.mode && targets == o.targets && elapsed == o.elapsed &&
                publicIp == o.publicIp && publicIpNote == o.publicIpNote &&
                resolver == o.resolver && transports == o.transports
}

class Dashboard(
    private val registry: Registry,
    private val sections: List<Section>,
    private val title: String,
    private val version: String
) {
    private val timeFmt = DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault())
    private val spinner = charArrayOf('\u280B', '\u2819', '\u2839', '\u2838', '\u283C', '\u2834', '\u2826', '\u2827', '\u2807', '\u280F')
    private var spin = 0
    private var lastFrame = ""
    private var lastHead: Headline? = null
    var lastRendered: String = ""
        private set

    fun tick() { spin++ }

    fun render(head: Headline, log: List<LogLine>, cols: Int, rows: Int): String {
        val w = cols.coerceIn(60, 200)
        val h = rows.coerceIn(12, 200)
        val lines = ArrayList<String>(h)

        val checksBySection = LinkedHashMap<String, MutableList<Check>>()
        for (s in sections) checksBySection[s.id] = mutableListOf()
        for (c in registry.checks) checksBySection.getOrPut(c.section) { mutableListOf() }.add(c)

        // ---- шапка
        val brand = Ansi.bold(Ansi.gradient("NetScope"))
        val tag = Ansi.gray("v$version")
        val tagline = Ansi.gray("сканер фильтрации " + Glyph.bullet() + " DPI " + Glyph.bullet() + " цензура " + Glyph.bullet() + " утечки " + Glyph.bullet() + " обфускация")
        lines += Ansi.fit("  $brand $tag   $tagline", w)

        // ---- мета
        val secs = head.elapsed / 1000
        val time = "%d:%02d".format(secs / 60, secs % 60)
        val meta = listOf(
            "профиль" to head.profile,
            "режим" to head.mode,
            "целей" to head.targets.toString(),
            "время" to time,
            "мой IP" to head.publicIp
        )
        var metaLine = "  " + Ansi.gray("meta  ") + Ansi.gray(meta.joinToString(Ansi.gray("  ${Glyph.vsep()}  ")) { (k, v) -> "$k ${Ansi.silver(v)}" })
        lines += Ansi.fit(metaLine, w)

        if (head.resolver != "—" || head.transports.isNotEmpty()) {
            val parts = ArrayList<String>()
            if (head.resolver != "—") parts += "резолвер ${Ansi.silver(head.resolver)}"
            if (head.transports.isNotEmpty()) parts += "транспорт ${Ansi.silver(head.transports)}"
            lines += Ansi.fit("  " + Ansi.gray("net   ") + Ansi.gray(parts.joinToString("  ${Glyph.vsep()}  ")), w)
        } else {
            lines += ""
        }

        // ---- прогресс
        val p = registry.progress
        val barW = (w - 34).coerceIn(10, 90)
        val bar = bar(p, barW)
        val sp = if (registry.checks.any { it.verdict == Verdict.RUN }) Ansi.blue(spinner[spin % spinner.size].toString()) else Ansi.gray("*")
        lines += Ansi.fit("  $sp  $bar  ${Ansi.silver("%3d%%".format((p * 100).toInt()))}  ${Ansi.gray("${registry.checks.count { it.verdict == Verdict.RUN }} активных")}", w)
        lines += Ansi.fit("  " + Ansi.gray(Glyph.sep().repeat(w - 2)), w)

        // ---- таблица
        val idW = 22
        val stW = 11
        val resW = (w - idW - stW - 6).coerceAtLeast(20)
        lines += Ansi.fit(
            "  " + Ansi.bold(Ansi.gray("СЕКЦИЯ".padEnd(idW))) + "  " + Ansi.bold(Ansi.gray("СТАТУС".padEnd(stW))) + "  " + Ansi.bold(Ansi.gray("РЕЗУЛЬТАТ")),
            w
        )
        lines += Ansi.fit("  " + Ansi.gray(Glyph.sep().repeat((w - 2).coerceAtLeast(10))), w)

        val sparkW = (w - idW - stW - resW - 10).coerceIn(0, 26)
        var runningSection = ""
        for (s in sections) {
            val list = checksBySection[s.id].orEmpty()
            val st = if (list.isEmpty()) Verdict.SKIP else Verdict.worstOf(list.map { it.verdict })
            val styled = Ansi.style(st.style, Ansi.pad(st.mark + " " + st.label, stW))
            val titleTxt = if (s.id == runningSection) s.title else s.title
            val spark = spark(list.map { it.verdict }, sparkW)
            val cell = buildString {
                append(Ansi.gray(Glyph.vsep()))
                append(' ')
                append(Ansi.fit(titleTxt, idW))
                append(' ')
                append(styled)
                append(' ')
                append(spark)
                append(' ')
            }
            val res = summarise(list, resW)
            val row = "  " + cell + Ansi.fit(res, resW)
            lines += Ansi.fit(row, w)
        }

        // ---- итог
        lines += ""
        lines += Ansi.fit("  " + verdictCard(w), w)
        lines += Ansi.fit("  " + Ansi.gray(Glyph.sep().repeat((w - 2).coerceAtLeast(10))), w)

        // ---- лог
        val used = lines.size
        val room = (h - used - 1).coerceAtLeast(0)
        val visible = if (room <= 0) emptyList() else log.takeLast(room)
        for (l in visible) lines += Ansi.fit(formatLog(l, w), w)

        while (lines.size < h) lines += ""
        if (lines.size > h) lines.subList(h, lines.size).clear()

        lastHead = head
        val joined = lines.joinToString("\r\n")
        lastRendered = joined
        return joined
    }

    private fun bar(p: Double, w: Int): String {
        val filled = (p * w).toInt()
        val sb = StringBuilder()
        sb.append(Ansi.gradient(Glyph.barFull().toString().repeat(filled.coerceIn(0, w))))
        if (filled < w) {
            val rem = w - filled
            sb.append(Ansi.gray(Glyph.barEmpty().toString().repeat(rem)))
        }
        return sb.toString()
    }

    private fun spark(verdicts: List<Verdict>, w: Int): String {
        if (w <= 0 || verdicts.isEmpty()) return ""
        val shown = verdicts.takeLast(w)
        return shown.joinToString("") {
            when (it) {
                Verdict.OK -> Ansi.green(Glyph.dotFilled())
                Verdict.WARN -> Ansi.yellow(Glyph.dotFilled())
                Verdict.FAIL -> Ansi.red(Glyph.dotFilled())
                Verdict.RUN -> Ansi.blue(Glyph.dotEmpty())
                Verdict.SKIP -> Ansi.gray(Glyph.dotEmpty())
                Verdict.INFO -> Ansi.cyan(Glyph.dotFilled())
            }
        }
    }

    private fun summarise(list: List<Check>, w: Int): String {
        if (list.isEmpty()) return Ansi.gray("ожидание")
        val done = list.count { it.verdict != Verdict.RUN }
        val worst = list.filter { it.verdict != Verdict.RUN }.maxByOrNull { it.verdict.weight }
        val text = if (worst != null && worst.detail.isNotBlank()) worst.detail else list.first().title
        val prefix = "$done/${list.size}  "
        return Ansi.fit(Ansi.style(worst?.verdict?.style ?: "dim", text), w - prefix.length) + Ansi.gray(prefix)
    }

    private fun verdictCard(w: Int): String {
        val all = registry.checks
        val fails = all.count { it.verdict == Verdict.FAIL }
        val warns = all.count { it.verdict == Verdict.WARN }
        val oks = all.count { it.verdict == Verdict.OK }
        val infos = all.count { it.verdict == Verdict.INFO }
        val crit = all.any { it.critical && it.verdict == Verdict.FAIL }
        val verdict = Verdict.worstOf(all.map { it.verdict })
        val head = when {
            crit -> "СРЕДА МОДИФИЦИРОВАНА"
            fails > 0 -> "ОБНАРУЖЕНЫ ПРИЗНАКИ ЦЕНЗУРЫ"
            warns > 0 -> "ЕСТЬ ЗАМЕЧАНИЯ"
            oks > 0 -> "ПРИЗНАКОВ ФИЛЬТРАЦИИ НЕТ"
            else -> "НЕТ ДАННЫХ"
        }
        val col = when {
            crit -> Ansi.bold(Ansi.red(head))
            fails > 0 -> Ansi.bold(Ansi.red(head))
            warns > 0 -> Ansi.bold(Ansi.yellow(head))
            else -> Ansi.bold(Ansi.green(head))
        }
        val counts = buildString {
            append(Ansi.green("$oks ок"))
            if (infos > 0) append(Ansi.gray("  ${Glyph.vsep()}  ")).append(Ansi.cyan("$infos инфо"))
            if (warns > 0) append(Ansi.gray("  ${Glyph.vsep()}  ")).append(Ansi.yellow("$warns вним."))
            if (fails > 0) append(Ansi.gray("  ${Glyph.vsep()}  ")).append(Ansi.red("$fails блок"))
        }
        val mark = when {
            crit || fails > 0 -> Ansi.red(Glyph.fail())
            warns > 0 -> Ansi.yellow(Glyph.warn())
            else -> Ansi.green(Glyph.ok())
        }
        val left = "  $mark  $col"
        val leftW = Ansi.width(left)
        return Ansi.fit(left, (w / 2).coerceAtLeast(20)) + Ansi.fit(counts, (w - w / 2).coerceAtLeast(20)) + ""
    }

    private fun formatLog(l: LogLine, w: Int): String {
        val t = Ansi.gray(timeFmt.format(l.at))
        val src = Ansi.cyan(Ansi.fit(l.source, 14))
        val lv = when (l.level) {
            Level.OK -> Ansi.green(Glyph.ok()); Level.FAIL -> Ansi.red(Glyph.fail())
            Level.WARN -> Ansi.yellow(Glyph.warn()); Level.INFO -> Ansi.blue(Glyph.arrow())
            Level.CRIT -> Ansi.magenta(Glyph.fail()); else -> Ansi.gray(Glyph.dotEmpty())
        }
        val textColor: (String) -> String = when (l.level) {
            Level.OK -> Ansi::silver; Level.FAIL -> Ansi::silver; Level.WARN -> Ansi::silver
            Level.CRIT -> Ansi::white; Level.INFO -> Ansi::gray; else -> Ansi::gray
        }
        val prefix = "$t $lv $src "
        val body = textColor(Ansi.fit(l.text, w - Ansi.width(prefix)))
        return prefix + body
    }

    fun changed(head: Headline, log: List<LogLine>, cols: Int, rows: Int): Boolean {
        val candidate = render(head, log, cols, rows)
        if (candidate == lastFrame) return false
        lastFrame = candidate
        return true
    }
}
