package netscope.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import netscope.core.Check
import netscope.core.Ctx
import netscope.core.Json
import netscope.core.Mode
import netscope.core.Verdict
import netscope.net.Http

class GeoProbe(private val ctx: Ctx) {
    suspend fun run() {
        identity()
        timezoneConsistency()
    }

    private suspend fun identity() {
        val c = ctx.reg.add(Check("geo.identity", "geo", "Географическая привязка"))
        val providers = listOf(
            "ipinfo.io" to "https://ipinfo.io/json",
            "ipapi.co" to "https://ipapi.co/json/",
            "ipwho.is" to "https://ipwho.is/"
        )
        val res = parMap(3, providers) { (n, u) -> n to Http.get(u, 5000, maxBody = 16384) }
        val parsed = res.mapNotNull { (n, r) ->
            if (r.status !in 200..299) return@mapNotNull null
            val j = Json.parse(r.text)
            val ip = j.field("ip")?.asString() ?: return@mapNotNull null
            Triple(n, ip, j)
        }
        if (parsed.isEmpty()) { c.set(Verdict.SKIP, "гео-сервисы недоступны"); return }
        val first = parsed.first()
        ctx.publicIpV4 = ctx.publicIpV4.ifEmpty { first.second }
        ctx.geoCountry = first.third.field("country")?.asString()
            ?: first.third.field("country_name")?.asString() ?: ""
        ctx.geoCountryCode = first.third.field("country_code")?.asString()
            ?: first.third.field("country_code")?.asString() ?: ""
        ctx.geoCity = first.third.field("city")?.asString() ?: ""
        ctx.geoOrg = first.third.field("org")?.asString() ?: first.third.field("organization")?.asString() ?: ""
        ctx.geoIsp = first.third.field("isp")?.asString() ?: ""
        // сравниваем по двузначному коду: «RU» и «Russian Federation» — это одна страна
        val codes = parsed.mapNotNull { (n, ip, j) ->
            j.field("country_code")?.asString()?.uppercase()
                ?: j.field("country")?.asString()?.takeIf { it.length == 2 }?.uppercase()
        }.distinct()
        c.set(
            when {
                codes.size > 1 -> Verdict.FAIL
                ctx.geoOrg.contains("VPN", true) || ctx.geoOrg.contains("hosting", true) ||
                        ctx.geoOrg.contains("data center", true) -> Verdict.WARN
                else -> Verdict.INFO
            },
            "${ctx.geoCountry.ifBlank { "?" }} ${ctx.geoCity} · ${ctx.geoOrg.take(40)}"
        )
        parsed.forEach { (n, ip, j) ->
            c.ev("  ${n.padEnd(10)} $ip  ${j.field("country")?.asString() ?: "?"} ${j.field("city")?.asString() ?: ""} ${j.field("org")?.asString() ?: ""}")
        }
        if (codes.size > 1) {
            c.ev("сервисы геолокации называют разные страны: " + codes.joinToString(", "))
            ctx.blockers.add("гео не сходится между сервисами")
        }
        if (ctx.geoOrg.contains("hosting", true) || ctx.geoOrg.contains("data center", true) || ctx.geoOrg.contains("VPN", true)) {
            c.ev("адрес принадлежит хостингу или VPN — сайты относятся к нему с подозрением и чаще показывают капчу")
        }
    }

    private suspend fun timezoneConsistency() {
        val c = ctx.reg.add(Check("geo.tz", "geo", "Часовой пояс и аномалии"))
        val tz = ctx.systemTz
        val local = java.time.LocalDateTime.now(java.time.ZoneId.systemDefault())
        val utc = java.time.LocalDateTime.now(java.time.ZoneOffset.UTC)
        val offsetMin = java.time.Duration.between(utc, local).toMinutes()
        val httpDate = withContext(Dispatchers.IO) {
            Http.get("https://cloudflare.com/", 4500, maxBody = 512).header("Date")
        }
        c.set(Verdict.INFO, "системный пояс $tz (UTC${if (offsetMin >= 0) "+" else ""}${(offsetMin / 60).toString() + ":" + (Math.abs(offsetMin) % 60).toString().padStart(2, '0')}), адрес: ${ctx.geoCountry.ifBlank { "?" }}")
        if (httpDate.isNotBlank()) c.ev("Date в ответе сервера: $httpDate")
        c.ev("расхождение часового пояса с реальным регионом — типовая утечка при неполной VPN")
        if (ctx.geoCountryCode.isNotBlank() && ctx.geoCountryCode.length == 2) {
            val expected = TZ_HINT[ctx.geoCountryCode.uppercase()]
            if (expected != null && !tz.uppercase().contains(expected)) {
                c.set(Verdict.WARN, "пояс $tz не похож на $expected для страны ${ctx.geoCountryCode.uppercase()}")
                c.ev("причины: ручная настройка, старый профиль, утечка реального региона через DNS или HTTP-заголовки")
                ctx.blockers.add("часовой пояс не соответствует стране выхода")
            }
        }
        if (ctx.opts.mode == Mode.DEEP) {
            val ms = withContext(Dispatchers.IO) { netscope.net.Proc.ping("1.1.1.1", 32, false, 1500) }
            val ttl = Regex("TTL=(\\d+)").find(ms.text)?.groupValues?.get(1)?.toIntOrNull()
            if (ttl != null) {
                val hops = when {
                    ttl >= 250 -> "8–12 хопов (близко или Linux-конец)"
                    ttl >= 128 -> "10–25 хопов (средняя дистанция)"
                    ttl >= 64 -> "20–50 хопов (дальний маршрут)"
                    else -> "50+ хопов (очень далеко или Windows-начало)"
                }
                c.ev("TTL ответа = $ttl → ориентировочно $hops")
                ctx.evidenceAll.add("TTL=$ttl")
            }
        }
    }

    companion object {
        private val TZ_HINT = mapOf(
            "RU" to "MOSCOW", "UA" to "KYIV", "BY" to "MINSK", "KZ" to "ALMATY", "DE" to "BERLIN",
            "US" to "", "NL" to "AMSTERDAM", "FI" to "HELSINKI", "SE" to "STOCKHOLM", "GB" to "LONDON",
            "PL" to "WARSAW", "TR" to "ISTANBUL", "AM" to "YEREVAN", "GE" to "TBILISI"
        )
    }
}
