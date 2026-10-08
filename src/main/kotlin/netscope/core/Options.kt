package netscope.core

import netscope.ui.Headline
import java.security.cert.X509Certificate

enum class Mode(val id: String, val title: String, val note: String) {
    QUICK("quick", "быстро", "базовая картина за ~30 с"),
    STANDARD("standard", "стандарт", "полный набор проверок"),
    DEEP("deep", "глубоко", "повторы, трассировка, расширенные пробы");

    companion object {
        fun parse(s: String?): Mode = entries.firstOrNull { it.id.equals(s, true) } ?: STANDARD
    }
}

class Options(
    val mode: Mode = Mode.STANDARD,
    val sections: Set<String> = emptySet(),
    val extraDomains: List<String> = emptyList(),
    val bridges: List<String> = emptyList(),
    val fetchBridges: Boolean = false,
    val timeoutMs: Int = 4000,
    val jsonOut: String? = null,
    val htmlOut: String? = null,
    val noColor: Boolean = false,
    val ascii: Boolean = false,
    val verbose: Boolean = false,
    val noLive: Boolean = false,
    val listDomains: Boolean = false,
    val certs: Boolean = false,
    val help: Boolean = false,
    val version: Boolean = false
)

/** Общее состояние прогона: то, что вычисляется один раз и переиспользуется секциями. */
class Ctx(val opts: Options, val reg: Registry, val head: Headline) {
    val systemResolvers: MutableList<String> = java.util.Collections.synchronizedList(mutableListOf<String>())
    var publicIpV4: String = ""
    var publicIpV6: String = ""
    var geoCountry: String = ""
    var geoCountryCode: String = ""
    var geoCity: String = ""
    var geoOrg: String = ""
    var geoIsp: String = ""
    var systemTz: String = java.util.TimeZone.getDefault().id
    var hostName: String = try { java.net.InetAddress.getLocalHost().hostName } catch (_: Throwable) { "?" }

    val certsSeen: MutableMap<String, X509Certificate> = java.util.Collections.synchronizedMap(LinkedHashMap())
    val blockers: MutableList<String> = java.util.Collections.synchronizedList(mutableListOf<String>())
    val evidenceAll: MutableList<String> = java.util.Collections.synchronizedList(mutableListOf<String>())

    var dpiDetected = false
    var sniBlocked = false
    var tlsInTls = "неизвестно"
    var fragTolerance = "неизвестно"
    var obfsFeasible = "неизвестно"
    var meekFeasible = "неизвестно"
    var snowflakeFeasible = "неизвестно"
    var rttBaseline: Long = 0
    var pathMtu: Int = -1
    var mtuHost = ""
}
