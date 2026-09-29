package netscope.core

sealed class Json {
    object Null : Json()
    data class Bool(val value: Boolean) : Json()
    data class Num(val value: Double) : Json()
    data class Str(val value: String) : Json()
    data class Arr(val items: List<Json>) : Json()
    data class Obj(val fields: Map<String, Json>) : Json()

    fun field(name: String): Json? = (this as? Obj)?.fields?.get(name)

    fun asList(): List<Json> = when (this) {
        is Arr -> items
        is Obj -> listOf(this)
        else -> emptyList()
    }

    fun asString(): String? = when (this) {
        is Str -> value
        is Num -> if (value == value.toLong().toDouble()) value.toLong().toString() else value.toString()
        is Bool -> value.toString()
        else -> null
    }

    fun asDouble(): Double? = when (this) {
        is Num -> value
        is Str -> value.trim().toDoubleOrNull()
        else -> null
    }

    fun render(indent: Int = 2): String = StringBuilder().also { write(it, 0, indent) }.toString()

    private fun write(sb: StringBuilder, depth: Int, indent: Int) {
        val pad = if (indent <= 0) "" else "\n" + " ".repeat(indent * (depth + 1))
        val padEnd = if (indent <= 0) "" else "\n" + " ".repeat(indent * depth)
        when (this) {
            is Null -> sb.append("null")
            is Bool -> sb.append(value)
            is Num -> sb.append(
                if (value == value.toLong().toDouble() && kotlin.math.abs(value) < 9.007199254740992E15) value.toLong().toString()
                else value.toString()
            )
            is Str -> escape(value, sb)
            is Arr -> {
                if (items.isEmpty()) { sb.append("[]"); return }
                sb.append('[')
                items.forEachIndexed { i, item ->
                    if (i > 0) sb.append(',')
                    sb.append(pad)
                    item.write(sb, depth + 1, indent)
                }
                sb.append(padEnd).append(']')
            }
            is Obj -> {
                if (fields.isEmpty()) { sb.append("{}"); return }
                sb.append('{')
                fields.entries.forEachIndexed { i, (k, v) ->
                    if (i > 0) sb.append(',')
                    sb.append(pad)
                    escape(k, sb)
                    sb.append(':').append(if (indent <= 0) "" else " ")
                    v.write(sb, depth + 1, indent)
                }
                sb.append(padEnd).append('}')
            }
        }
    }

    companion object {
        fun of(value: Any?): Json = when (value) {
            null -> Null
            is Json -> value
            is Boolean -> Bool(value)
            is Int, is Long, is Short, is Byte -> Num((value as Number).toDouble())
            is Float, is Double -> Num((value as Number).toDouble())
            is String -> Str(value)
            is Enum<*> -> Str(value.name)
            is Map<*, *> -> Obj(value.entries.associate { (k, v) -> k.toString() to of(v) })
            is Iterable<*> -> Arr(value.map { of(it) })
            is Array<*> -> Arr(value.map { of(it) })
            is IntArray -> Arr(value.map { of(it) })
            is LongArray -> Arr(value.map { of(it) })
            else -> Str(value.toString())
        }

        private fun escape(s: String, sb: StringBuilder) {
            sb.append('"')
            for (c in s) when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c < ' ' || c == '\u007f') sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
            sb.append('"')
        }

        fun parse(text: String): Json = Parser(text).run {
            skipWs()
            val v = value()
            v
        }

        private class Parser(val s: String) {
            var i = 0
            fun skipWs() {
                while (i < s.length && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) i++
            }
            fun expect(c: Char): Boolean { skipWs(); if (i < s.length && s[i] == c) { i++; return true }; return false }
            fun value(): Json {
                skipWs()
                if (i >= s.length) return Null
                return when (s[i]) {
                    '{' -> obj()
                    '[' -> arr()
                    '"' -> Str(string())
                    't' -> { i += 4; Bool(true) }
                    'f' -> { i += 5; Bool(false) }
                    'n' -> { i += 4; Null }
                    else -> number()
                }
            }
            fun obj(): Json {
                expect('{')
                val m = LinkedHashMap<String, Json>()
                skipWs()
                if (i < s.length && s[i] == '}') { i++; return Obj(m) }
                while (i < s.length) {
                    skipWs()
                    val k = if (i < s.length && s[i] == '"') string() else s.substring(i).takeWhile { it != ':' }.trim()
                    if (i < s.length && s[i] == '"') i++
                    i++ // ':'
                    m[k] = value()
                    skipWs()
                    if (i < s.length && s[i] == ',') { i++; continue }
                    if (i < s.length && s[i] == '}') { i++; break }
                    break
                }
                return Obj(m)
            }
            fun arr(): Json {
                expect('[')
                val l = ArrayList<Json>()
                skipWs()
                if (i < s.length && s[i] == ']') { i++; return Arr(l) }
                while (i < s.length) {
                    l.add(value())
                    skipWs()
                    if (i < s.length && s[i] == ',') { i++; continue }
                    if (i < s.length && s[i] == ']') { i++; break }
                    break
                }
                return Arr(l)
            }
            fun string(): String {
                val sb = StringBuilder()
                if (i < s.length && s[i] == '"') i++
                while (i < s.length) {
                    val c = s[i]
                    when {
                        c == '\\' -> {
                            i++
                            when (val e = s[i]) {
                                'n' -> sb.append('\n'); 'r' -> sb.append('\r'); 't' -> sb.append('\t')
                                'b' -> sb.append('\b'); 'f' -> sb.append('\u000c')
                                'u' -> { sb.append(s.substring(i + 1, i + 5).toInt(16).toChar()); i += 4 }
                                else -> sb.append(e)
                            }
                            i++
                        }
                        c == '"' -> { i++; break }
                        else -> { sb.append(c); i++ }
                    }
                }
                return sb.toString()
            }
            fun number(): Json {
                val start = i
                while (i < s.length && (s[i].isDigit() || s[i] in "+-eE.")) i++
                if (start == i) { i++; return Str(s.substring(start, i)) }
                return s.substring(start, i).toDoubleOrNull()?.let { Num(it) } ?: Str(s.substring(start, i))
            }
        }
    }
}
