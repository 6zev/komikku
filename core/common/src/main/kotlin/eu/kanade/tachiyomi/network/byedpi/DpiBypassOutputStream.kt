package eu.kanade.tachiyomi.network.byedpi

import java.io.ByteArrayOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import kotlin.math.min
import kotlin.random.Random

/**
 * Output stream that tries to defeat stateful DPI by splitting the first payload written on a
 * connection (TLS ClientHello or plain HTTP request) into multiple small TCP writes.
 *
 * The implementation is intentionally conservative: only the very first payload of a connection is
 * touched, every following byte is forwarded as-is.
 */
internal class DpiBypassOutputStream(
    private val delegate: OutputStream,
    private val mode: Int,
) : FilterOutputStream(delegate) {

    private var processed = false
    private val pending = ByteArrayOutputStream()

    override fun write(b: Int) {
        if (processed) {
            delegate.write(b)
            return
        }
        pending.write(b)
        tryProcess()
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (processed) {
            delegate.write(b, off, len)
            return
        }
        pending.write(b, off, len)
        tryProcess()
    }

    override fun flush() {
        if (!processed) {
            val data = pending.toByteArray()
            // A TLS ClientHello may be split across several writes; keep waiting for the whole
            // record instead of fragmenting a truncated handshake.
            if (data.isNotEmpty() && !isIncompleteTls(data)) {
                processed = true
                pending.reset()
                process(data)
            }
        }
        delegate.flush()
    }

    private fun isIncompleteTls(data: ByteArray): Boolean =
        data.size >= 2 &&
            data[0] == 0x16.toByte() &&
            data[1] == 0x03.toByte() &&
            !isReady(data)

    private fun tryProcess() {
        val data = pending.toByteArray()
        if (!isReady(data)) return
        processed = true
        pending.reset()
        process(data)
    }

    private fun isReady(data: ByteArray): Boolean {
        if (data.size < 2) return false
        if (data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
            if (data.size < 6) return false
            val recordLength = u16(data, 3)
            return data.size >= 5 + recordLength || data.size >= MAX_HELLO_SIZE
        }
        return data.size >= 5
    }

    private fun process(data: ByteArray) {
        if (isTlsHandshake(data)) {
            val sni = findSni(data)
            if (sni != null) {
                writeTlsFragments(data, sni)
            } else {
                splitFirst(data)
            }
        } else if (mode == ByeDpiMode.AGGRESSIVE && isHttpRequest(data)) {
            writeHttpDesync(data)
        } else {
            splitFirst(data)
        }
        delegate.flush()
    }

    private fun writeTlsFragments(data: ByteArray, sni: SniInfo) {
        val payloadLength = u16(data, 3)
        val recordEnd = 5 + payloadLength
        if (recordEnd > data.size) {
            splitFirst(data)
            return
        }

        val points = splitPoints(sni, recordEnd)
        var offset = 5
        for ((index, end) in points.withIndex()) {
            val length = end - offset
            if (length <= 0) continue
            delegate.write(0x16)
            delegate.write(data[1].toInt() and 0xFF)
            delegate.write(data[2].toInt() and 0xFF)
            delegate.write((length shr 8) and 0xFF)
            delegate.write(length and 0xFF)
            delegate.write(data, offset, length)
            delegate.flush()
            offset = end
            if (index < points.lastIndex) delay()
        }

        if (recordEnd < data.size) {
            delegate.write(data, recordEnd, data.size - recordEnd)
            delegate.flush()
        }
    }

    private fun splitPoints(sni: SniInfo, recordEnd: Int): List<Int> {
        val points = mutableListOf<Int>()
        val before = sni.offset
        if (before > 5 + MIN_FRAGMENT) points += before

        val middle = sni.offset + sni.length / 2
        if (middle > (points.lastOrNull() ?: 5) + MIN_FRAGMENT && middle < recordEnd - MIN_FRAGMENT) {
            points += middle
        }

        val after = sni.offset + sni.length
        if (after > (points.lastOrNull() ?: 5) + MIN_FRAGMENT && after < recordEnd - MIN_FRAGMENT) {
            points += after
        }

        points += recordEnd
        if (points.size <= 1) {
            val early = 5 + min(MIN_FRAGMENT, (recordEnd - 5) / 3)
            if (early < recordEnd - MIN_FRAGMENT) points.add(0, early)
        }
        return points
    }

    private fun splitFirst(data: ByteArray) {
        if (data.size <= 1) {
            delegate.write(data)
            delegate.flush()
            return
        }
        delegate.write(data, 0, 1)
        delegate.flush()
        delay()
        delegate.write(data, 1, data.size - 1)
        delegate.flush()
    }

    private fun writeHttpDesync(data: ByteArray) {
        val text = String(data, Charsets.ISO_8859_1)
        val lineEnd = text.indexOf("\r\n")
        if (lineEnd <= 0) {
            splitFirst(data)
            return
        }

        val requestLine = text.substring(0, lineEnd) + "\r\n"
        val headers = text.substring(lineEnd + 2)
            .replaceFirst(Regex("(?im)^Host:"), "${mixCase("Host")}:")
            .replace(Regex("(?i)(Host:\\s*)([^\\r\\n]+)")) { match ->
                val host = match.groupValues[2].trimEnd()
                val value = if (!host.contains(':') && !host.endsWith('.')) "$host." else host
                "${match.groupValues[1]}$value"
            }

        delegate.write(requestLine.toByteArray(Charsets.ISO_8859_1))
        delegate.flush()
        delay()
        delegate.write(headers.toByteArray(Charsets.ISO_8859_1))
        delegate.flush()
    }

    private fun findSni(data: ByteArray): SniInfo? {
        if (data.size < 44) return null
        if (data[0] != 0x16.toByte() || data[1] != 0x03.toByte()) return null

        val recordLength = u16(data, 3)
        if (recordLength < 42 || 5 + recordLength > data.size) return null

        var position = 5
        if (data[position].toInt() and 0xFF != 0x01) return null
        position += 4 + 2 + 32
        if (position >= data.size) return null

        val sessionLength = data[position].toInt() and 0xFF
        position += 1 + sessionLength
        if (position + 2 > data.size) return null

        val cipherLength = u16(data, position)
        position += 2 + cipherLength
        if (position >= data.size) return null

        val compressionLength = data[position].toInt() and 0xFF
        position += 1 + compressionLength
        if (position + 2 > data.size) return null

        val extensionsLength = u16(data, position)
        position += 2
        val extensionsEnd = min(position + extensionsLength, data.size)

        while (position + 4 <= extensionsEnd) {
            val type = u16(data, position)
            val length = u16(data, position + 2)
            val dataStart = position + 4
            val dataEnd = dataStart + length
            if (dataEnd > extensionsEnd) return null

            if (type == 0x0000 && dataStart + 2 <= dataEnd) {
                val listEnd = min(dataStart + 2 + u16(data, dataStart), dataEnd)
                var namePosition = dataStart + 2
                while (namePosition + 3 <= listEnd) {
                    val nameType = data[namePosition].toInt() and 0xFF
                    val nameLength = u16(data, namePosition + 1)
                    val nameStart = namePosition + 3
                    if (nameStart + nameLength > listEnd) break
                    if (nameType == 0) return SniInfo(nameStart, nameLength)
                    namePosition = nameStart + nameLength
                }
            }

            position = dataEnd
        }
        return null
    }

    private fun isTlsHandshake(data: ByteArray): Boolean {
        if (data.size < 6) return false
        return data[0] == 0x16.toByte() &&
            data[1] == 0x03.toByte() &&
            data[5].toInt() and 0xFF == 0x01
    }

    private fun isHttpRequest(data: ByteArray): Boolean {
        val firstLine = String(data, Charsets.ISO_8859_1).substringBefore("\r\n")
        val parts = firstLine.split(' ')
        if (parts.size < 2) return false
        return parts[0].uppercase() in HTTP_METHODS
    }

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun delay() = Thread.sleep(Random.nextLong(20L, 61L))

    private fun mixCase(value: String): String {
        val mixed = value.map {
            if (Random.nextBoolean()) it.uppercaseChar() else it.lowercaseChar()
        }.joinToString("")
        return if (mixed == value) value.replaceFirstChar { it.lowercaseChar() } else mixed
    }

    private data class SniInfo(val offset: Int, val length: Int)

    private companion object {
        private const val MAX_HELLO_SIZE = 32 * 1024
        private const val MIN_FRAGMENT = 4
        private val HTTP_METHODS = setOf(
            "GET",
            "POST",
            "HEAD",
            "PUT",
            "DELETE",
            "OPTIONS",
            "CONNECT",
            "PATCH",
        )
    }
}
