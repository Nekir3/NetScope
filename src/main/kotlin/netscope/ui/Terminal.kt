package netscope.ui

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import java.io.PrintStream

internal interface Kernel32Console : Library {
    fun SetConsoleMode(h: Pointer, mode: Int): Int
    fun GetConsoleMode(h: Pointer, mode: IntArray): Int
    fun GetConsoleScreenBufferInfo(h: Pointer, info: ScreenBufferInfo): Int
    fun GetStdHandle(which: Int): Pointer?
}

@Structure.FieldOrder(
    "sizeX", "sizeY", "curX", "curY", "attributes",
    "winLeft", "winTop", "winRight", "winBottom", "maxX", "maxY"
)
internal class ScreenBufferInfo : Structure() {
    @JvmField var sizeX: Short = 0
    @JvmField var sizeY: Short = 0
    @JvmField var curX: Short = 0
    @JvmField var curY: Short = 0
    @JvmField var attributes: Short = 0
    @JvmField var winLeft: Short = 0
    @JvmField var winTop: Short = 0
    @JvmField var winRight: Short = 0
    @JvmField var winBottom: Short = 0
    @JvmField var maxX: Short = 0
    @JvmField var maxY: Short = 0
}

/**
 * Терминальный слой: включение VT-последовательностей, размер окна,
 * переключение в альтернативный экран. Спонтанно деградирует до 100x30.
 */
class Terminal(private val out: PrintStream = System.out) {
    val isWindows: Boolean = System.getProperty("os.name").lowercase().contains("win")
    var virtualTerminal: Boolean = false
        private set

    private var k32: Kernel32Console? = null

    init {
        if (isWindows) {
            try {
                k32 = Native.load("kernel32", Kernel32Console::class.java)
            } catch (_: Throwable) {
                k32 = null
            }
        }
    }

    /** Включает обработку ANSI-последовательностей. Возвращает true, если терминал готов к live-рендеру. */
    fun enableAnsi(): Boolean {
        if (!isWindows) { virtualTerminal = true; return true }
        val k = k32 ?: return false
        virtualTerminal = try {
            val handle = k.GetStdHandle(STD_OUTPUT_HANDLE)
            val mode = IntArray(1)
            if (handle != null && k.GetConsoleMode(handle, mode) != 0) {
                val m = mode[0]
                if (m and ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0) true
                else k.SetConsoleMode(handle, m or ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
            } else {
                false
            }
        } catch (_: Throwable) {
            false
        }
        return virtualTerminal
    }
    fun size(): Pair<Int, Int> {
        val k = k32
        if (k != null) {
            try {
                val handle = k.GetStdHandle(STD_OUTPUT_HANDLE)
                if (handle != null) {
                    val info = ScreenBufferInfo()
                    if (k.GetConsoleScreenBufferInfo(handle, info) != 0) {
                        val cols = (info.winRight - info.winLeft + 1).toInt()
                        val rows = (info.winBottom - info.winTop + 1).toInt()
                        if (cols > 10 && rows > 5) return cols.coerceAtMost(200) to rows.coerceAtMost(200)
                    }
                }
            } catch (_: Throwable) { /* fall through */ }
        }
        envSize()?.let { return it }
        if (isWindows) modeConSize()?.let { return it }
        return 100 to 34
    }

    private fun envSize(): Pair<Int, Int>? {
        val c = System.getenv("COLUMNS")?.toIntOrNull()
        val l = System.getenv("LINES")?.toIntOrNull()
        return if (c != null && l != null && c > 10 && l > 5) c to l else null
    }

    private fun modeConSize(): Pair<Int, Int>? = try {
        val p = ProcessBuilder("cmd", "/c", "mode", "con").redirectErrorStream(true).start()
        val text = p.inputStream.bufferedReader().readText()
        p.waitFor()
        val nums = Regex(":\\s*(\\d+)").findAll(text).map { it.groupValues[1].toInt() }.toList()
        if (nums.size >= 2 && nums[0] > 10 && nums[1] > 5) nums[0] to nums[1] else null
    } catch (_: Throwable) { null }

    fun write(s: String) {
        out.print(s)
        out.flush()
    }

    fun enterLive() {
        if (!virtualTerminal) return
        write(Ansi.altScreen(true) + Ansi.HIDE + Ansi.CLEAR)
    }

    fun exitLive() {
        if (!virtualTerminal) return
        write(Ansi.SHOW + Ansi.altScreen(false))
    }

    companion object {
        const val STD_OUTPUT_HANDLE = -11
        const val STD_INPUT_HANDLE = -10
        const val ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
    }
}
