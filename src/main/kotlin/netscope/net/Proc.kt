package netscope.net

import java.io.File
import java.util.concurrent.TimeUnit

data class ProcResult(val out: String, val err: String, val code: Int, val ms: Long, val failed: Boolean = false) {
    val text: String get() = out.ifBlank { err }
}

object Proc {
    fun raw(cmd: List<String>, timeoutMs: Int = 8000, dir: File? = null): ProcResult {
        val t0 = System.currentTimeMillis()
        return try {
            val pb = ProcessBuilder(cmd).redirectErrorStream(false)
            if (dir != null) pb.directory(dir)
            val p = pb.start()
            val so = StringBuilder()
            val se = StringBuilder()
            val t1 = Thread { runCatching { p.inputStream.bufferedReader(Charsets.UTF_8).forEachLine { so.append(it).append('\n') } } }
            val t2 = Thread { runCatching { p.errorStream.bufferedReader(Charsets.UTF_8).forEachLine { se.append(it).append('\n') } } }
            t1.isDaemon = true; t2.isDaemon = true
            t1.start(); t2.start()
            val done = p.waitFor(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            if (!done) { p.destroyForcibly(); ProcResult(so.toString(), se.toString(), -1, System.currentTimeMillis() - t0, true) }
            else { t1.join(500); t2.join(500); ProcResult(so.toString(), se.toString(), p.exitValue(), System.currentTimeMillis() - t0) }
        } catch (e: Throwable) {
            ProcResult("", e.message ?: e::class.java.simpleName, -1, System.currentTimeMillis() - t0, true)
        }
    }

    /** Запуск консольной утилиты Windows с принудительным UTF-8 выводом. */
    fun console(command: String, timeoutMs: Int = 8000): ProcResult {
        val full = "chcp 65001>nul & $command"
        return raw(listOf("cmd", "/c", full), timeoutMs)
    }

    fun powershell(script: String, timeoutMs: Int = 20000): ProcResult {
        val wrapped = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $script"
        return raw(listOf("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", wrapped), timeoutMs)
    }

    fun ping(host: String, size: Int = 1400, df: Boolean = true, timeoutMs: Int = 2500): ProcResult {
        val args = buildList {
            add("ping"); add("-n"); add("1"); add("-w"); add(timeoutMs.toString())
            if (df) { add("-f"); add("-l"); add(size.toString()) }
            add(host)
        }
        return raw(args, timeoutMs + 1500)
    }

    fun tracert(host: String, hops: Int = 20, waitMs: Int = 900): ProcResult =
        raw(listOf("tracert", "-d", "-h", hops.toString(), "-w", waitMs.toString(), host), (hops * waitMs + 5000).toInt())

    fun available(cmd: String): Boolean = try {
        val p = ProcessBuilder("cmd", "/c", "where $cmd").redirectErrorStream(true).start()
        val ok = p.inputStream.bufferedReader().readText().isNotBlank()
        p.waitFor(3000, TimeUnit.MILLISECONDS)
        ok
    } catch (_: Throwable) { false }
}
