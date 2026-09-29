package netscope.core

object Targets {
    data class Lists(
        val control: List<String>,
        val suspect: List<String>,
        val egress: List<String>,
        val fronting: List<String>,
        val quic: List<String>,
        val stun: List<String>
    )

    private val builtin = Lists(
        control = listOf("cloudflare.com", "google.com", "github.com", "wikipedia.org", "akamai.com", "cdnjs.cloudflare.com"),
        suspect = listOf("facebook.com", "instagram.com", "x.com", "reddit.com", "telegram.org", "duckduckgo.com", "signal.org", "archive.org"),
        egress = listOf("api.ipify.org", "api64.ipify.org", "icanhazip.com", "ifconfig.me", "checkip.amazonaws.com"),
        fronting = listOf("ajax.aspnetcdn.com", "www.gstatic.com", "cdn.jsdelivr.net", "unpkg.com", "github.githubassets.com"),
        quic = listOf("cloudflare.com", "www.google.com"),
        stun = listOf("stun.l.google.com", "stun.cloudflare.com", "stun.nextcloud.com")
    )

    fun load(extraDomains: List<String> = emptyList()): Lists {
        var lists = builtin
        val text = runCatching {
            Targets::class.java.getResourceAsStream("/netscope/domains.txt")?.bufferedReader(Charsets.UTF_8)?.readText()
        }.getOrNull()
        if (!text.isNullOrBlank()) {
            val map = LinkedHashMap<String, MutableList<String>>()
            var current = "control"
            for (raw in text.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue
                if (line.startsWith("@")) { current = line.substring(1).lowercase(); map.getOrPut(current) { mutableListOf() }; continue }
                map.getOrPut(current) { mutableListOf() }.add(line)
            }
            fun pick(key: String, fallback: List<String>) = map[key]?.takeIf { it.isNotEmpty() } ?: fallback
            lists = Lists(
                control = pick("control", builtin.control),
                suspect = pick("suspect", builtin.suspect),
                egress = pick("egress", builtin.egress),
                fronting = pick("fronting", builtin.fronting),
                quic = pick("quic", builtin.quic),
                stun = pick("stun", builtin.stun)
            )
        }
        if (extraDomains.isNotEmpty()) {
            val merged = (lists.suspect + extraDomains).distinct()
            lists = lists.copy(suspect = merged, control = (lists.control + extraDomains).distinct())
        }
        return lists
    }

    val publicResolvers = listOf(
        "1.1.1.1" to "Cloudflare",
        "1.0.0.1" to "Cloudflare",
        "8.8.8.8" to "Google",
        "8.8.4.4" to "Google",
        "9.9.9.9" to "Quad9",
        "149.112.112.112" to "Quad9",
        "94.140.14.14" to "AdGuard",
        "185.228.168.9" to "CleanBrowsing",
        "208.67.222.222" to "OpenDNS",
        "77.88.8.8" to "Yandex",
        "77.88.8.1" to "Yandex"
    )

    /** Порты, где любой middlebox обязательно себя выдаёт. */
    val portMatrix = listOf(80, 443, 8080, 8443, 1080, 8118, 8888, 9001, 9030, 9050)

    /** Порты, на которых обычно публикуют obfs4/snowflake-мосты. */
    val bridgePorts = listOf(443, 80, 5443, 9001, 9022, 9030, 8888)

    val portService = mapOf(
        80 to "HTTP", 443 to "HTTPS", 1080 to "SOCKS", 8080 to "HTTP-прокси", 8118 to "HTTP-прокси",
        8443 to "alt-HTTPS", 8888 to "HTTP-прокси", 9001 to "Tor ORPort", 9030 to "Tor ControlPort", 9050 to "Tor SOCKS"
    )
}
