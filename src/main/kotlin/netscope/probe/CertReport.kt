package netscope.probe

import netscope.core.Ctx
import netscope.core.Json
import netscope.core.Targets
import netscope.net.Mitm
import netscope.net.NetError
import netscope.net.Tls
import netscope.net.symbol

/** Итог одной попытки получить сертификат: доступен ли он и можно ли ему доверять. */
data class CertRow(
    val host: String,
    val reachable: Boolean,
    val trusted: Boolean?,
    val issuer: String = "",
    val subject: String = "",
    val notAfter: String = "",
    val daysLeft: Long = 0,
    val chainLength: Int = 0,
    val protocol: String = "",
    val cipher: String = "",
    val sigAlg: String = "",
    val pubKey: String = "",
    val san: List<String> = emptyList(),
    val fingerprint: String = "",
    val ms: Long = 0,
    val error: String = "",
    val netError: NetError = NetError.NONE,
    val trustError: String = ""
) {
    enum class Status { OK, UNTRUSTED, UNREACHABLE }

    val status: Status get() = when {
        !reachable -> Status.UNREACHABLE
        trusted == false -> Status.UNTRUSTED
        else -> Status.OK
    }

    val reason: String get() = when {
        !reachable -> netError.symbol() + if (error.isNotBlank()) "  ${error.take(70)}" else ""
        trusted == false -> trustError.take(90)
        else -> ""
    }

    fun markers(): List<String> = Mitm.matches(issuer + " " + subject)
}

object CertReport {

    /** Все домены, которые имеет смысл показать: эталоны, подозрительные и добавленные через --domain. */
    fun targets(ctx: Ctx): List<String> {
        val t = Targets.load(ctx.opts.extraDomains)
        return (t.control + t.suspect).distinct()
    }

    suspend fun collect(ctx: Ctx, domains: List<String>, limit: Int = 6): List<CertRow> =
        parMap(limit, domains) { d -> row(d, Tls.probe(d, 443, 5000)) }

    private fun row(host: String, i: netscope.net.TlsInfo): CertRow {
        if (!i.ok) {
            return CertRow(
                host = host, reachable = false, trusted = null,
                ms = i.ms, error = i.error, netError = i.netError
            )
        }
        val leaf = i.leaf
        return CertRow(
            host = host, reachable = true, trusted = i.publiclyTrusted,
            issuer = i.issuer, subject = i.subject,
            notAfter = i.notAfter, daysLeft = i.daysLeft,
            chainLength = i.chainLength, protocol = i.protocol, cipher = i.cipherSuite,
            sigAlg = i.sigAlg, pubKey = i.pubKey, san = i.san,
            fingerprint = leaf?.let { Mitm.sha256(it) } ?: "",
            ms = i.ms, trustError = i.trustError
        )
    }

    fun table(rows: List<CertRow>, width: Int): String {
        val w = width.coerceIn(70, 160)
        val out = StringBuilder()
        out.append('\n')
        out.append("  ").append(netscope.ui.Ansi.bold(netscope.ui.Ansi.gradient("ИНВЕНТАРИЗАЦИЯ СЕРТИФИКАТОВ"))).append('\n')
        out.append("  ").append(netscope.ui.Ansi.gray("${rows.size} доменов · " +
                "доступно ${rows.count { it.status == CertRow.Status.OK }} · " +
                "без публичного доверия ${rows.count { it.status == CertRow.Status.UNTRUSTED }} · " +
                "недоступно ${rows.count { it.status == CertRow.Status.UNREACHABLE }}"))
        out.append('\n')

        fun head(col: String, w2: Int) = netscope.ui.Ansi.gray(netscope.ui.Ansi.fit(col, w2))
        out.append("  ").append(head("", 3))
            .append(head("ДОМЕН", 22))
            .append(head("СТАТУС", 14))
            .append(head("СРОК", 12))
            .append(head("CA / ПРИЧИНА", (w - 56).coerceAtLeast(24)))
            .append('\n')
        out.append("  ").append(netscope.ui.Ansi.gray("─".repeat((w - 4).coerceIn(40, 150)))).append('\n')

        val order = listOf(CertRow.Status.UNREACHABLE, CertRow.Status.UNTRUSTED, CertRow.Status.OK)
        for (r in rows.sortedBy { order.indexOf(it.status) }) {
            val style = when (r.status) {
                CertRow.Status.OK -> "green"
                CertRow.Status.UNTRUSTED -> "yellow"
                CertRow.Status.UNREACHABLE -> "red"
            }
            val mark = when (r.status) {
                CertRow.Status.OK -> netscope.ui.Glyph.ok()
                CertRow.Status.UNTRUSTED -> netscope.ui.Glyph.warn()
                CertRow.Status.UNREACHABLE -> netscope.ui.Glyph.fail()
            }
            val label = when (r.status) {
                CertRow.Status.OK -> "доступен"
                CertRow.Status.UNTRUSTED -> "без доверия"
                CertRow.Status.UNREACHABLE -> "недоступен"
            }
            val term = if (r.reachable) {
                if (r.daysLeft in 0..30) "${r.daysLeft} дн.!" else "${r.daysLeft} дн."
            } else ""
            val tail = if (r.reachable) r.issuer else r.netError.name
            out.append("  ")
                .append(netscope.ui.Ansi.style(style, mark)).append(' ')
                .append(netscope.ui.Ansi.silver(netscope.ui.Ansi.fit(r.host, 21)))
                .append(netscope.ui.Ansi.style(style, netscope.ui.Ansi.fit(label, 14)))
                .append(netscope.ui.Ansi.gray(netscope.ui.Ansi.fit(term, 12)))
                .append(netscope.ui.Ansi.cut(tail, (w - 56).coerceAtLeast(24)))
                .append('\n')
        }

        val bad = rows.filter { it.status != CertRow.Status.OK }
        if (bad.isNotEmpty()) {
            out.append('\n')
            out.append("  ").append(netscope.ui.Ansi.bold(netscope.ui.Ansi.red("ПОДРОБНЕЕ"))).append('\n')
            bad.forEach { r ->
                out.append("    ").append(netscope.ui.Ansi.style(
                    if (r.status == CertRow.Status.UNREACHABLE) "red" else "yellow",
                    when (r.status) {
                        CertRow.Status.UNREACHABLE -> netscope.ui.Glyph.fail()
                        else -> netscope.ui.Glyph.warn()
                    })).append(' ')
                    .append(netscope.ui.Ansi.bold(r.host)).append('\n')
                out.append("      ").append(netscope.ui.Ansi.gray(r.reason.ifBlank { "—" })).append('\n')
                if (r.reachable) {
                    out.append("      ").append(netscope.ui.Ansi.gray(
                        "до ${r.notAfter} · ${r.sigAlg} · ${r.pubKey} · цепочка ${r.chainLength} · ${r.ms} мс")).append('\n')
                    r.markers().forEach {
                        out.append("      ").append(netscope.ui.Ansi.red("маркер перехвата: $it")).append('\n')
                    }
                }
            }
        }
        out.append('\n')
        return out.toString()
    }

    fun json(rows: List<CertRow>): String {
        val items = rows.map { r ->
            Json.Obj(mapOf(
                "host" to Json.Str(r.host),
                "status" to Json.Str(r.status.name.lowercase()),
                "reachable" to Json.Bool(r.reachable),
                "trusted" to (r.trusted?.let { Json.Bool(it) } ?: Json.Null),
                "issuer" to Json.Str(r.issuer),
                "subject" to Json.Str(r.subject),
                "not_after" to Json.Str(r.notAfter),
                "days_left" to Json.Num(r.daysLeft.toDouble()),
                "chain_length" to Json.Num(r.chainLength.toDouble()),
                "protocol" to Json.Str(r.protocol),
                "cipher" to Json.Str(r.cipher),
                "sig_alg" to Json.Str(r.sigAlg),
                "pub_key" to Json.Str(r.pubKey),
                "fingerprint" to Json.Str(r.fingerprint),
                "san" to Json.Arr(r.san.map { Json.Str(it) }),
                "ms" to Json.Num(r.ms.toDouble()),
                "net_error" to Json.Str(r.netError.name),
                "error" to Json.Str(r.error),
                "trust_error" to Json.Str(r.trustError)
            ))
        }
        return Json.Obj(mapOf(
            "tool" to Json.Str("NetScope"),
            "kind" to Json.Str("certificates"),
            "total" to Json.Num(rows.size.toDouble()),
            "unreachable" to Json.Num(rows.count { it.status == CertRow.Status.UNREACHABLE }.toDouble()),
            "untrusted" to Json.Num(rows.count { it.status == CertRow.Status.UNTRUSTED }.toDouble()),
            "certificates" to Json.Arr(items)
        )).render(2)
    }
}
