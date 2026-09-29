package netscope.ui

object Ansi {
    @Volatile var enabled: Boolean = true
    @Volatile var unicode: Boolean = true

    private val ESC = "\u001B["

    fun wrap(code: String, s: String): String = if (!enabled || s.isEmpty()) s else "$ESC${code}m$s${ESC}0m"

    fun bold(s: String) = wrap("1", s)
    fun dim(s: String) = wrap("2", s)
    fun italic(s: String) = wrap("3", s)
    fun underline(s: String) = wrap("4", s)
    fun inverse(s: String) = wrap("7", s)

    fun black(s: String) = wrap("38;5;232", s)
    fun red(s: String) = wrap("38;5;203", s)
    fun green(s: String) = wrap("38;5;114", s)
    fun yellow(s: String) = wrap("38;5;179", s)
    fun blue(s: String) = wrap("38;5;75", s)
    fun magenta(s: String) = wrap("38;5;176", s)
    fun cyan(s: String) = wrap("38;5;80", s)
    fun gray(s: String) = wrap("38;5;245", s)
    fun silver(s: String) = wrap("38;5;252", s)
    fun white(s: String) = wrap("38;5;255", s)

    fun style(name: String, s: String): String = when (name) {
        "green" -> green(s); "red" -> red(s); "yellow" -> yellow(s); "blue" -> blue(s)
        "cyan" -> cyan(s); "magenta" -> magenta(s); "dim" -> gray(s); else -> s
    }

    fun gradient(s: String): String {
        if (!enabled) return s
        val steps = arrayOf("45", "51", "87", "123", "159", "195", "231")
        val per = (s.length + steps.size - 1) / steps.size
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val chunk = s.substring(i, minOf(s.length, i + per))
            sb.append(wrap("38;5;${steps[(i / per).coerceAtMost(steps.size - 1)]}", chunk))
            i += per
        }
        return sb.toString()
    }

    // control sequences
    const val CLEAR = "\u001B[2J\u001B[H"
    const val HOME = "\u001B[H"
    const val HIDE = "\u001B[?25l"
    const val SHOW = "\u001B[?25h"
    fun altScreen(enter: Boolean) = if (enter) "\u001B[?1049h" else "\u001B[?1049l"
    fun clearLine() = "\u001B[K"
    fun cursorUp(n: Int) = if (n > 0) "\u001B[${n}F" else ""
    fun cursorTo(row: Int, col: Int) = "\u001B[${row};${col}H"

    private val ansiRegex = Regex("\u001B\\[[0-9;?]*[a-zA-Z]")

    fun strip(s: String): String = ansiRegex.replace(s, "")

    fun width(s: String): Int {
        var w = 0
        var i = 0
        val t = strip(s)
        while (i < t.length) {
            val cp = t.codePointAt(i)
            val n = Character.charCount(cp)
            w += charWidth(cp)
            i += n
        }
        return w
    }

    private fun charWidth(cp: Int): Int {
        if (cp == 0) return 0
        if (cp in 0x0300..0x036F) return 0
        if (cp in 0x200B..0x200F) return 0
        if (cp in 0xFE00..0xFE0F) return 0
        return when {
            cp < 0x20 -> 0
            cp < 0x7F -> 1
            cp in 0x1100..0x115F -> 2
            cp in 0x2E80..0xA4CF -> 2
            cp in 0xAC00..0xD7A3 -> 2
            cp in 0xF900..0xFAFF -> 2
            cp in 0xFE30..0xFE6F -> 2
            cp in 0xFF00..0xFF60 -> 2
            cp in 0xFFE0..0xFFE6 -> 2
            cp in 0x1F300..0x1F64F -> 2
            cp in 0x1F900..0x1F9FF -> 2
            cp in 0x1F680..0x1F6FF -> 2
            else -> 1
        }
    }

    fun pad(s: String, w: Int): String {
        val d = w - width(s)
        return if (d <= 0) s else s + " ".repeat(d)
    }

    fun cut(s: String, w: Int): String {
        if (width(s) <= w) return s
        val sb = StringBuilder()
        var acc = 0
        var i = 0
        val t = strip(s)
        while (i < t.length) {
            val cp = t.codePointAt(i)
            val cw = charWidth(cp)
            if (acc + cw > w - 1) break
            sb.appendCodePoint(cp)
            acc += cw
            i += Character.charCount(cp)
        }
        return sb.toString() + "…"
    }

    fun fit(s: String, w: Int): String = if (width(s) > w) cut(s, w) else pad(s, w)
}

object Glyph {
    @Volatile var ascii: Boolean = false
    private fun pick(uni: String, asc: String) = if (AsciiMode || ascii) asc else uni
    @Volatile var AsciiMode = false

    val ok = { pick("✔", "+") }
    val fail = { pick("✖", "x") }
    val warn = { pick("▲", "!") }
    val info = { pick("•", "*") }
    val run = { pick("◌", "~") }
    val skip = { pick("·", "-") }
    val arrow = { pick("→", "->") }
    val bullet = { pick("▸", ">") }
    val barFull = { pick("█", "#") }
    val barHalf = { pick("▌", "=") }
    val barEmpty = { pick("░", ".") }
    val dotFilled = { pick("●", "*") }
    val dotEmpty = { pick("○", "o") }
    val boxH = { pick("─", "-") }
    val boxV = { pick("│", "|") }
    val tl = { pick("╭", "+") }
    val tr = { pick("╮", "+") }
    val bl = { pick("╰", "+") }
    val br = { pick("╯", "+") }
    val sep = { pick("─", "-") }
    val vsep = { pick("│", "|") }
    val arrowSmall = { pick("›", ">") }
    val clock = { pick("◷", "T") }
    val shield = { pick("◈", "#") }
    val wave = { pick("≈", "~") }
}
