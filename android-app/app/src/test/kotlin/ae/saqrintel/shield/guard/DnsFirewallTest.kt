package ae.saqrintel.shield.guard

import ae.saqrintel.shield.data.BlockEntry
import ae.saqrintel.shield.data.BlockMatcher
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class DnsFirewallTest {

    /** A DNS query (type A, class IN) for [name], wrapped in IPv4 + UDP from 10.111.222.1:40000 to 10.111.222.2:53. */
    private fun queryPacket(name: String, id: Int = 0x1234, dstPort: Int = 53): ByteArray {
        val qname = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray(Charsets.US_ASCII).toList() } + 0
        val dns = byteArrayOf((id shr 8).toByte(), id.toByte(), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) +
            qname.toByteArray() + byteArrayOf(0, 1, 0, 1)
        val udpLen = 8 + dns.size
        val total = 20 + udpLen
        val ip = ByteArray(20)
        ip[0] = 0x45
        ip[2] = (total shr 8).toByte()
        ip[3] = total.toByte()
        ip[8] = 64
        ip[9] = 17
        byteArrayOf(10, 111, 222.toByte(), 1).copyInto(ip, 12)
        byteArrayOf(10, 111, 222.toByte(), 2).copyInto(ip, 16)
        val udp = byteArrayOf((40000 shr 8).toByte(), 40000.toByte(), (dstPort shr 8).toByte(), dstPort.toByte(), (udpLen shr 8).toByte(), udpLen.toByte(), 0, 0)
        return ip + udp + dns
    }

    @Test
    fun readsTheNameADnsQueryAsksFor() {
        val p = queryPacket("Pay.TAMM-Fine.top")
        val q = DnsPacket.parse(p, p.size)
        assertNotNull(q)
        assertEquals("pay.tamm-fine.top", q!!.host)
        assertEquals(40000, q.srcPort)
        assertEquals(53, q.dstPort)
    }

    @Test
    fun ignoresEverythingThatIsNotADnsQuery() {
        val web = queryPacket("example.com", dstPort = 443)
        assertNull(DnsPacket.parse(web, web.size))
        assertNull(DnsPacket.parse(ByteArray(10), 10))
        val v6 = queryPacket("example.com").also { it[0] = 0x60 }
        assertNull(DnsPacket.parse(v6, v6.size))
        val tcp = queryPacket("example.com").also { it[9] = 6 }
        assertNull(DnsPacket.parse(tcp, tcp.size))
    }

    @Test
    fun blockedAnswerSaysNoSuchNameAndKeepsTheQuestion() {
        val p = queryPacket("tamm-fine.top", id = 0xBEEF)
        val q = DnsPacket.parse(p, p.size)!!
        val answer = DnsPacket.nxdomain(q.dns)!!
        assertEquals(0xBE.toByte(), answer[0])
        assertEquals(0xEF.toByte(), answer[1])
        assertEquals(0x80, answer[2].toInt() and 0x80) // a response
        assertEquals(3, answer[3].toInt() and 0x0f) // NXDOMAIN
        assertEquals(0, answer[7].toInt()) // no answers
        assertArrayEquals(q.dns.copyOfRange(12, q.dns.size), answer.copyOfRange(12, answer.size))
        assertNull(DnsPacket.questionName(answer)) // a response is never read as a query
    }

    @Test
    fun replyPacketGoesBackToTheAsker() {
        val p = queryPacket("example.com")
        val q = DnsPacket.parse(p, p.size)!!
        val reply = DnsPacket.wrap(q, DnsPacket.nxdomain(q.dns)!!)
        assertArrayEquals(byteArrayOf(10, 111, 222.toByte(), 2), reply.copyOfRange(12, 16)) // from the DNS address
        assertArrayEquals(byteArrayOf(10, 111, 222.toByte(), 1), reply.copyOfRange(16, 20)) // to the phone
        assertEquals(53, ((reply[20].toInt() and 0xff) shl 8) or (reply[21].toInt() and 0xff))
        assertEquals(40000, ((reply[22].toInt() and 0xff) shl 8) or (reply[23].toInt() and 0xff))
        assertEquals(reply.size, ((reply[2].toInt() and 0xff) shl 8) or (reply[3].toInt() and 0xff))
        // IPv4 header checksum: all 16-bit words must sum to 0xffff
        var sum = 0
        for (i in 0 until 20 step 2) sum += ((reply[i].toInt() and 0xff) shl 8) or (reply[i + 1].toInt() and 0xff)
        while (sum shr 16 != 0) sum = (sum and 0xffff) + (sum shr 16)
        assertEquals(0xffff, sum)
    }

    private val index = BlockMatcher.index(
        listOf(
            BlockEntry("tamm-fine.top", 100.0, "TAMM Abu Dhabi"),
            BlockEntry("saqr-demo-scam.vercel.app", 100.0, "TAMM Abu Dhabi"),
            BlockEntry("adpolice.gov.ae", 90.0), // a bad list entry must never block an official site
            BlockEntry("saqr-intel.vercel.app", 70.0), // ... nor Saqr itself
        ),
    )

    @Test
    fun listedSitesAndTheirSubdomainsAreBlocked() {
        assertEquals("tamm-fine.top", BlockMatcher.find("tamm-fine.top", index)?.domain)
        assertEquals("tamm-fine.top", BlockMatcher.find("pay.tamm-fine.top.", index)?.domain)
        assertEquals("saqr-demo-scam.vercel.app", BlockMatcher.find("SAQR-demo-scam.vercel.app", index)?.domain)
    }

    @Test
    fun otherSitesOfficialSitesAndSaqrItselfAreNeverBlocked() {
        assertNull(BlockMatcher.find("vercel.app", index)) // the platform is not the listed site
        assertNull(BlockMatcher.find("other-project.vercel.app", index))
        assertNull(BlockMatcher.find("nottamm-fine.top", index)) // not a sub-domain
        assertNull(BlockMatcher.find("www.adpolice.gov.ae", index))
        assertNull(BlockMatcher.find("saqr-intel.vercel.app", index))
        assertNull(BlockMatcher.find("top", index))
        assertNull(BlockMatcher.find(null, index))
        assertNull(BlockMatcher.find("tamm-fine.top", emptyMap()))
    }
}
