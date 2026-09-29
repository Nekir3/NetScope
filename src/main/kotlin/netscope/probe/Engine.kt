package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import netscope.core.Ctx
import netscope.core.Registry
import netscope.core.Section
import java.time.Instant

val SECTIONS = listOf(
    Section("env", "Окружение", "адаптеры, прокси, MTU, маршрут"),
    Section("dns", "Честность DNS", "система против DoH, перехват, подмена"),
    Section("tcp", "TCP и порты", "достижимость, фильтрация по порту"),
    Section("http", "HTTP", "код, заголовки, вмешательство, скорость"),
    Section("tls", "TLS и SNI", "сертификаты, версии, видимость SNI"),
    Section("dpi", "DPI-сигнатуры", "RST-инъекции, фрагментация, обфускация"),
    Section("mitm", "Перехват трафика", "подмена сертификатов, чужой CA"),
    Section("leaks", "Утечки", "IP, DNS, WebRTC, IPv6, адаптеры"),
    Section("geo", "Гео и аномалии", "страна, часовой пояс, TTL"),
    Section("bridges", "Обфускация и мосты", "obfs4, snowflake, meek")
)

suspend fun <T> par(limit: Int, block: suspend (Int) -> T): List<T> = coroutineScope {
    val sem = Semaphore(limit)
    (0 until limit).map { async { sem.withPermit { block(it) } } }.awaitAll()
}

suspend fun <T, R> parMap(limit: Int, items: List<T>, block: suspend (T) -> R): List<R> = coroutineScope {
    if (items.isEmpty()) return@coroutineScope emptyList()
    val sem = Semaphore(limit)
    items.map { item -> async(Dispatchers.IO) { sem.withPermit { block(item) } } }.awaitAll()
}

fun Registry.now() = Instant.now()
