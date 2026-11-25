package ae.saqrintel.shield.guard

import java.util.Locale

/**
 * Just enough IPv4 / UDP / DNS to run the scam-site firewall: read the name a DNS query asks for, build a
 * "this name does not exist" answer, and wrap an answer back into an IP packet. Pure Kotlin (unit-tested).
 */
object DnsPacket {
    private const val IP_HEADER = 20
    private const val UDP_HEADER = 8
    private const val DNS_HEADER = 12
    private const val DNS_PORT = 53

    /** One DNS question taken off the tunnel. `dns` is the DNS message itself. */
    class Query(
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        val dns: ByteArray,
        /** Lower-cased name without a trailing dot, or null when the question cannot be read. */
        val host: String?,
    )

    private fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xff
    private fun u16(b: ByteArray, i: Int) = (u8(b, i) shl 8) or u8(b, i + 1)
    private fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v shr 8).toByte()
        b[i + 1] = v.toByte()
    }

    /** An IPv4 UDP packet to port 53, or null for anything else (it is simply dropped). */
    fun parse(packet: ByteArray, length: Int): Query? {
        if (length < IP_HEADER + UDP_HEADER + DNS_HEADER) return null
        if (u8(packet, 0) shr 4 != 4) return null // IPv4 only
        val ihl = (u8(packet, 0) and 0x0f) * 4
        if (ihl < IP_HEADER || length < ihl + UDP_HEADER + DNS_HEADER) return null
        if (u8(packet, 9) != 17) return null // UDP only
        if (u16(packet, 6) and 0x3fff != 0) return null // fragments are not reassembled
        val total = minOf(u16(packet, 2), length)
        val srcPort = u16(packet, ihl)
        val dstPort = u16(packet, ihl + 2)
        if (dstPort != DNS_PORT) return null
        val udpLen = u16(packet, ihl + 4)
        val end = minOf(total, ihl + udpLen)
        val start = ihl + UDP_HEADER
        if (end - start < DNS_HEADER) return null
        val dns = packet.copyOfRange(start, end)
        return Query(
            srcIp = packet.copyOfRange(12, 16),
            dstIp = packet.copyOfRange(16, 20),
            srcPort = srcPort,
            dstPort = dstPort,
            dns = dns,
            host = questionName(dns),
        )
    }

    /** End offset of the first question (name + type + class), or -1. */
    private fun questionEnd(dns: ByteArray): Int {
        if (dns.size < DNS_HEADER || u16(dns, 4) < 1) return -1
        var i = DNS_HEADER
        while (true) {
            if (i >= dns.size) return -1
            val len = u8(dns, i)
            if (len == 0) break
            if (len and 0xc0 != 0) return -1 // a query never uses compression
            i += len + 1
        }
        val end = i + 1 + 4
        return if (end <= dns.size) end else -1
    }

    /** The name in the first question: "www.example.com" (lower-case), or null. */
    fun questionName(dns: ByteArray): String? {
        if (questionEnd(dns) < 0) return null
        if (u8(dns, 2) and 0x80 != 0) return null // a response, not a query
        val sb = StringBuilder()
        var i = DNS_HEADER
        while (true) {
            val len = u8(dns, i)
            if (len == 0) break
            if (sb.isNotEmpty()) sb.append('.')
            for (k in 1..len) {
                val ch = u8(dns, i + k)
                if (ch < 0x21 || ch > 0x7e) return null // names on the wire are ASCII (IDN = xn--)
                sb.append(ch.toChar())
            }
            i += len + 1
            if (sb.length > 253) return null
        }
        return sb.toString().lowercase(Locale.ROOT).takeIf { it.isNotEmpty() }
    }

    /** "No such name" (NXDOMAIN) for this query: same id and question, no answers. Null if unreadable. */
    fun nxdomain(dns: ByteArray): ByteArray? {
        val end = questionEnd(dns)
        if (end < 0) return null
        val out = dns.copyOfRange(0, end)
        out[2] = (0x80 or (u8(dns, 2) and 0x79)).toByte() // response; keep opcode and "recursion desired"
        out[3] = (0x80 or 0x03).toByte() // recursion available, RCODE 3 = name error
        put16(out, 4, 1) // one question
        put16(out, 6, 0)
        put16(out, 8, 0)
        put16(out, 10, 0)
        return out
    }

    /** The reply packet for [q] carrying [payload] (addresses and ports swapped). */
    fun wrap(q: Query, payload: ByteArray): ByteArray {
        val total = IP_HEADER + UDP_HEADER + payload.size
        val p = ByteArray(total)
        p[0] = 0x45
        put16(p, 2, total)
        put16(p, 6, 0x4000) // don't fragment
        p[8] = 64
        p[9] = 17
        System.arraycopy(q.dstIp, 0, p, 12, 4)
        System.arraycopy(q.srcIp, 0, p, 16, 4)
        put16(p, 10, ipChecksum(p))
        put16(p, IP_HEADER, q.dstPort)
        put16(p, IP_HEADER + 2, q.srcPort)
        put16(p, IP_HEADER + 4, UDP_HEADER + payload.size)
        put16(p, IP_HEADER + 6, 0) // UDP checksum is optional over IPv4
        System.arraycopy(payload, 0, p, IP_HEADER + UDP_HEADER, payload.size)
        return p
    }

    private fun ipChecksum(header: ByteArray): Int {
        var sum = 0
        for (i in 0 until IP_HEADER step 2) {
            if (i == 10) continue
            sum += u16(header, i)
        }
        while (sum shr 16 != 0) sum = (sum and 0xffff) + (sum shr 16)
        return sum.inv() and 0xffff
    }
}
