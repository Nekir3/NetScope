package netscope.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.io.IOException
import java.net.ConnectException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.PortUnreachableException
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

object Sys {
    val isWindows: Boolean = System.getProperty("os.name").lowercase().contains("win")
    val isLinux: Boolean = System.getProperty("os.name").lowercase().contains("linux")
}

fun nanoMs(): Long = System.nanoTime() / 1_000_000

enum class NetError { NONE, TIMEOUT, REFUSED, RESET, UNREACHABLE, NO_ROUTE, DNS, SSL, EOF, UNKNOWN }

fun NetError.symbol(): String = when (this) {
    NetError.NONE -> "ok"
    NetError.TIMEOUT -> "таймаут (чёрная дыра)"
    NetError.REFUSED -> "отказ (RST/closed)"
    NetError.RESET -> "TCP RST"
    NetError.UNREACHABLE -> "хост недостижим"
    NetError.NO_ROUTE -> "нет маршрута"
    NetError.DNS -> "DNS-ошибка"
    NetError.SSL -> "TLS-ошибка"
    NetError.EOF -> "разрыв соединения"
    NetError.UNKNOWN -> "неизвестно"
}

fun classify(e: Throwable): NetError = when (e) {
    is SocketTimeoutException -> NetError.TIMEOUT
    is ConnectException -> NetError.REFUSED
    is NoRouteToHostException -> NetError.NO_ROUTE
    is PortUnreachableException -> NetError.NO_ROUTE
    is UnknownHostException -> NetError.DNS
    is SocketException -> {
        val m = e.message?.lowercase() ?: ""
        when {
            m.contains("reset") -> NetError.RESET
            m.contains("refused") -> NetError.REFUSED
            m.contains("unreachable") -> NetError.UNREACHABLE
            m.contains("no route") -> NetError.NO_ROUTE
            m.contains("aborted") -> NetError.EOF
            else -> NetError.UNKNOWN
        }
    }
    is javax.net.ssl.SSLException -> NetError.SSL
    is IOException -> NetError.UNKNOWN
    else -> NetError.UNKNOWN
}

data class TcpOutcome(
    val label: String,
    val host: String,
    val port: Int,
    val connected: Boolean,
    val ms: Long,
    val error: NetError = NetError.NONE,
    val message: String = "",
    val localAddr: String = "",
    val remoteAddr: String = ""
) {
    val ok: Boolean get() = connected
}

object Tcp {
    suspend fun connect(host: String, port: Int, timeoutMs: Int = 3000, label: String = "$host:$port"): TcpOutcome =
        withContext(Dispatchers.IO) { connectBlocking(host, port, timeoutMs, label) }

    fun connectBlocking(host: String, port: Int, timeoutMs: Int = 3000, label: String = "$host:$port"): TcpOutcome {
        val started = nanoMs()
        var sock: Socket? = null
        return try {
            val ai = InetAddress.getAllByName(host)
            sock = Socket()
            sock.tcpNoDelay = true
            sock.connect(InetSocketAddress(ai[0], port), timeoutMs)
            TcpOutcome(
                label = label, host = host, port = port, connected = true, ms = nanoMs() - started,
                localAddr = "${sock.localAddress}:${sock.localPort}",
                remoteAddr = "${sock.inetAddress}:${sock.port}"
            )
        } catch (e: Throwable) {
            TcpOutcome(label, host, port, false, nanoMs() - started, classify(e), e.message ?: e::class.java.simpleName)
        } finally {
            runCatching { sock?.close() }
        }
    }
}

/**
 * Сырой TCP-канал: даёт полный контроль над тем, когда и какими байтами писать,
 * и позволяет измерять время прихода RST/алерта/первого байта ответа.
 * Это основа всех DPI-экспериментов.
 */
class Wire private constructor(private val sock: Socket, val local: String, val remote: String) : Closeable {
    val out = sock.getOutputStream()
    private val input = sock.getInputStream()

    fun write(b: ByteArray, off: Int = 0, len: Int = b.size) { out.write(b, off, len); out.flush() }

    fun writeAll(vararg chunks: ByteArray) { chunks.forEach { write(it) } }

    /** @return число прочитанных байт, -1 при EOF; бросает SocketException при RST. */
    fun read(buf: ByteArray, timeoutMs: Int): Int {
        sock.soTimeout = timeoutMs
        return input.read(buf)
    }

    override fun close() { runCatching { sock.close() } }

    companion object {
        fun open(host: String, port: Int, timeoutMs: Int): Wire {
            val ai = InetAddress.getAllByName(host)
            val s = Socket()
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(ai[0], port), timeoutMs)
            return Wire(s, "${s.localAddress}:${s.localPort}", "${s.inetAddress}:${s.port}")
        }
    }
}

data class ProbeRead(
    val state: ReadState,
    val msFirstByte: Long,
    val bytes: Int,
    val buffer: ByteArray = ByteArray(0),
    val error: NetError = NetError.NONE,
    val message: String = ""
)

enum class ReadState { DATA, EOF, RESET, TIMEOUT, ERROR }

object Wire0 {
    /**
     * Открывает соединение, отправляет [payload] (опционально несколькими частями
     * с паузами) и читает до первого ответа. Возвращает точные тайминги —
     * именно по ним определяется RST-инъекция middlebox'а.
     */
    fun handshake(
        host: String, port: Int, timeoutMs: Int, payload: List<ByteArray>,
        gapMs: Long = 0, readTimeoutMs: Int = 2000, keepOpen: Boolean = false
    ): Triple<ProbeRead?, Wire?, NetError> {
        val wire = try { Wire.open(host, port, timeoutMs) } catch (e: Throwable) { return Triple(null, null, classify(e)) }
        val t0 = nanoMs()
        try {
            for ((i, chunk) in payload.withIndex()) {
                wire.write(chunk)
                if (gapMs > 0 && i < payload.size - 1) Thread.sleep(gapMs)
            }
            val buf = ByteArray(8192)
            val n = wire.read(buf, readTimeoutMs)
            val dt = nanoMs() - t0
            if (n < 0) return Triple(ProbeRead(ReadState.EOF, dt, 0), if (keepOpen) wire else null, NetError.EOF)
            return Triple(ProbeRead(ReadState.DATA, dt, n, buf.copyOf(n)), if (keepOpen) wire else null, NetError.NONE)
        } catch (e: Throwable) {
            val dt = nanoMs() - t0
            val err = classify(e)
            val state = if (err == NetError.RESET || err == NetError.REFUSED) ReadState.RESET else ReadState.ERROR
            return Triple(ProbeRead(state, dt, 0, error = err, message = e.message ?: ""), null, err)
        } finally {
            if (!keepOpen) runCatching { wire.close() }
        }
    }
}

fun String.isPrivateAddress(): Boolean {
    val parts = this.split('.', ':', '%')
    return when {
        startsWith("10.") || startsWith("192.168.") -> true
        matches(Regex("^172\\.(1[6-9]|2\\d|3[01])\\..*")) -> true
        startsWith("127.") || startsWith("0.") -> true
        startsWith("169.254.") -> true
        this == "::1" || startsWith("fe80:") || startsWith("fc") || startsWith("fd") -> true
        else -> parts.size >= 2 && false
    }
}

fun inetIsV6(a: InetAddress) = a is Inet6Address
fun inetIsV4(a: InetAddress) = a is Inet4Address
