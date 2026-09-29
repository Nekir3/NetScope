package netscope.core

import kotlinx.coroutines.channels.Channel
import java.time.Instant

enum class Verdict(val label: String, val mark: String, val style: String, val weight: Int) {
    OK("ОК", "✔", "green", 0),
    INFO("ИНФО", "•", "cyan", 1),
    WARN("ВНИМАНИЕ", "▲", "yellow", 2),
    FAIL("БЛОК", "✖", "red", 3),
    SKIP("ПРОПУЩЕНО", "·", "dim", -1),
    RUN("ИДЁТ", "◌", "blue", 0);

    companion object {
        fun worstOf(list: List<Verdict>): Verdict = when {
            list.any { it == FAIL } -> FAIL
            list.any { it == WARN } -> WARN
            list.any { it == INFO } -> INFO
            list.any { it == OK } -> OK
            list.any { it == SKIP } -> SKIP
            else -> RUN
        }
    }
}

enum class Level(val style: String) {
    TRACE("dim"), DEBUG("dim"), INFO("blue"), OK("green"), WARN("yellow"), FAIL("red"), CRIT("magenta")
}

data class LogLine(
    val at: Instant,
    val level: Level,
    val source: String,
    val text: String
)

class Check(
    val id: String,
    val section: String,
    val title: String,
    var verdict: Verdict = Verdict.RUN,
    var detail: String = "",
    var durationMs: Long = -1,
    var critical: Boolean = false,
    val evidence: MutableList<String> = mutableListOf()
) {
    internal val t0: Long = System.nanoTime()
    fun elapsedMs(): Long = (System.nanoTime() - t0) / 1_000_000

    fun set(v: Verdict, d: String) { verdict = v; detail = d }
    fun ev(vararg lines: String) { lines.forEach { evidence.add(it) } }
    fun toJson(): Json = Json.Obj(
        buildMap {
            put("id", Json.Str(id))
            put("section", Json.Str(section))
            put("title", Json.Str(title))
            put("verdict", Json.Str(verdict.name))
            put("detail", Json.Str(detail))
            if (durationMs >= 0) put("duration_ms", Json.Num(durationMs.toDouble()))
            put("critical", Json.Bool(critical))
            if (evidence.isNotEmpty()) put("evidence", Json.Arr(evidence.map { Json.Str(it) }))
        }
    )
}

data class Section(
    val id: String,
    val title: String,
    val hint: String = ""
)

class Registry {
    val checks = java.util.concurrent.CopyOnWriteArrayList<Check>()
    private val _log = Channel<LogLine>(Channel.UNLIMITED)
    val log: Channel<LogLine> = _log

    fun add(check: Check): Check { checks.add(check); return check }

    fun emit(level: Level, source: String, text: String) {
        _log.trySend(LogLine(Instant.now(), level, source, text))
    }
    fun trace(source: String, text: String) = emit(Level.TRACE, source, text)
    fun debug(source: String, text: String) = emit(Level.DEBUG, source, text)
    fun info(source: String, text: String) = emit(Level.INFO, source, text)
    fun ok(source: String, text: String) = emit(Level.OK, source, text)
    fun warn(source: String, text: String) = emit(Level.WARN, source, text)
    fun fail(source: String, text: String) = emit(Level.FAIL, source, text)

    fun close() { _log.close() }

    val progress: Double
        get() {
            val all = checks
            if (all.isEmpty()) return 0.0
            return all.count { it.verdict != Verdict.RUN }.toDouble() / all.size
        }
}
