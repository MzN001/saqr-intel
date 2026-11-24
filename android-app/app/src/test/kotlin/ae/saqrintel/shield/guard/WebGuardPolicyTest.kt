package ae.saqrintel.shield.guard

import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.guard.WebGuardPolicy.Action
import ae.saqrintel.shield.guard.WebGuardPolicy.Skip
import ae.saqrintel.shield.util.Defang
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WebGuardNormaliseTest {
    private fun n(s: String?) = WebGuardPolicy.normalise(s)

    @Test fun addsSchemeAndLowercasesHost() {
        val t = n("WWW.Example.COM/Path?x=1")!!
        assertEquals("https://www.example.com/Path?x=1", t.url)
        assertEquals("www.example.com", t.host)
        assertEquals("/Path", t.path)
    }

    @Test fun privateHostGetsHttpAndKeepsPort() {
        val t = n("10.0.2.2:8011/mock-scam/tamm-fine")!!
        assertEquals("http://10.0.2.2:8011/mock-scam/tamm-fine", t.url)
        assertEquals(8011, t.port)
        assertTrue(t.isMockScam)
        assertEquals("10.0.2.2/mock-scam/tamm-fine", t.key)
    }

    @Test fun keepsExplicitSchemeAndStripsFragment() {
        assertEquals("http://evil.example/a", n("http://evil.example/a#top")!!.url)
        assertEquals("https://evil.example", n("HTTPS://Evil.Example")!!.url)
    }

    @Test fun credentialsTrickUsesRealHost() {
        assertEquals("evil.com", n("https://tamm.abudhabi@evil.com/pay")!!.host)
    }

    @Test fun ignoresNonWebAndEmpty() {
        assertNull(n(null))
        assertNull(n(""))
        assertNull(n("   "))
        assertNull(n("about:blank"))
        assertNull(n("chrome://flags"))
        assertNull(n("chrome-native://newtab/"))
        assertNull(n("javascript:alert(1)"))
        assertNull(n("file:///sdcard/x.html"))
        assertNull(n("data:text/html,hi"))
    }

    @Test fun ignoresSearchQueriesAndTitles() {
        assertNull(n("pay my tamm fine"))
        assertNull(n("Example Domain"))
        assertNull(n("newtab"))
    }

    @Test fun ignoresSearchResultPages() {
        assertNull(n("https://www.google.com/search?q=tamm"))
        assertNull(n("google.co.ae/search?q=x"))
        assertNull(n("www.google.ae"))
        assertNull(n("duckduckgo.com/?q=x"))
        assertNull(n("https://www.bing.com/search?q=x"))
        // Not Google: a look-alike that only contains the word.
        assertEquals("google-login.example", n("google-login.example")!!.host)
        assertEquals("www.bing.com", n("www.bing.com/maps")!!.host)
    }

    @Test fun localhostWithPortIsNotAScheme() {
        val t = n("localhost:8011/mock-scam/x")!!
        assertEquals("localhost", t.host)
        assertEquals("http://localhost:8011/mock-scam/x", t.url)
    }

    @Test fun privateHosts() {
        listOf("127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "172.31.255.1", "169.254.1.1", "localhost", "[::1]")
            .forEach { assertTrue(it, WebGuardPolicy.isPrivateHost(it)) }
        listOf("172.32.0.1", "8.8.8.8", "example.com", "11.0.0.1").forEach { assertFalse(it, WebGuardPolicy.isPrivateHost(it)) }
    }
}

class WebGuardSkipTest {
    private fun t(s: String) = WebGuardPolicy.normalise(s)!!
    private val api = "saqr-intel-api.onrender.com"

    @Test fun officialDomainsAreNeverSent() {
        assertEquals(Skip.OFFICIAL, WebGuardPolicy.skipReason(t("https://www.adpolice.gov.ae"), api, emptySet()))
        assertEquals(Skip.OFFICIAL, WebGuardPolicy.skipReason(t("tamm.abudhabi/fines"), api, emptySet()))
        assertNull(WebGuardPolicy.skipReason(t("adpolice.gov.ae.evil.com"), api, emptySet()))
    }

    @Test fun privateHostsOnlyForMockScam() {
        assertEquals(Skip.PRIVATE, WebGuardPolicy.skipReason(t("192.168.1.1/admin"), api, emptySet()))
        assertNull(WebGuardPolicy.skipReason(t("192.168.1.5:8000/mock-scam/tamm-fine"), api, emptySet()))
    }

    @Test fun apiHostOnlyForMockScam() {
        assertEquals(Skip.API_HOST, WebGuardPolicy.skipReason(t("https://saqr-intel-api.onrender.com/health"), api, emptySet()))
        assertNull(WebGuardPolicy.skipReason(t("https://saqr-intel-api.onrender.com/mock-scam/tamm-fine"), api, emptySet()))
        val local = "10.0.2.2:8011"
        assertEquals(Skip.API_HOST, WebGuardPolicy.skipReason(t("10.0.2.2:8011/docs"), local, emptySet()))
        assertNull(WebGuardPolicy.skipReason(t("10.0.2.2:8011/mock-scam/tamm-fine"), local, emptySet()))
    }

    @Test fun allowListWins() {
        assertEquals(Skip.ALLOWED, WebGuardPolicy.skipReason(t("10.0.2.2:8011/mock-scam/tamm-fine"), null, setOf("10.0.2.2")))
        assertEquals(Skip.ALLOWED, WebGuardPolicy.skipReason(t("tamm-pay.example/x"), api, setOf("tamm-pay.example")))
    }

    @Test fun ordinarySiteIsChecked() {
        assertNull(WebGuardPolicy.skipReason(t("https://example.com"), api, emptySet()))
    }

    @Test fun apiHostParsing() {
        assertEquals("10.0.2.2:8011", SaqrBrowserGuardService.apiHostOf("http://10.0.2.2:8011"))
        assertEquals("saqr-intel-api.onrender.com", SaqrBrowserGuardService.apiHostOf("https://saqr-intel-api.onrender.com"))
        assertNull(SaqrBrowserGuardService.apiHostOf("not a url"))
    }
}

class WebGuardDecisionTest {
    @Test fun thresholds() {
        assertEquals(Action.BLOCK, WebGuardPolicy.action(Verdict.SCAM, 40))
        assertEquals(Action.BLOCK, WebGuardPolicy.action(Verdict.SUSPICIOUS, 65))
        assertEquals(Action.BLOCK, WebGuardPolicy.action(Verdict.SAFE, 90))
        assertEquals(Action.CAUTION, WebGuardPolicy.action(Verdict.SUSPICIOUS, 64))
        assertEquals(Action.CAUTION, WebGuardPolicy.action(Verdict.SAFE, 30))
        assertEquals(Action.NONE, WebGuardPolicy.action(Verdict.SAFE, 29))
        assertEquals(Action.NONE, WebGuardPolicy.action(Verdict.SAFE, null))
    }

    @Test fun deepScanOnlyForTheMiddleBand() {
        assertTrue(WebGuardPolicy.wantsDeepScan(Verdict.SUSPICIOUS, 45))
        assertFalse(WebGuardPolicy.wantsDeepScan(Verdict.SCAM, 80))
        assertFalse(WebGuardPolicy.wantsDeepScan(Verdict.SAFE, 10))
    }
}

class WebGuardThrottleTest {
    private var clock = 1_000_000L

    @Test fun cooldownPerUrl() {
        val th = UrlThrottle(5_000) { clock }
        assertTrue(th.tryStart("a.com", "a.com"))
        th.finish("a.com")
        clock += 4_999
        assertFalse(th.tryStart("a.com", "a.com"))
        clock += 1
        assertTrue(th.tryStart("a.com", "a.com"))
    }

    @Test fun inFlightDedupePerHost() {
        val th = UrlThrottle(5_000) { clock }
        assertTrue(th.tryStart("h/mock-scam/a", "h"))
        assertFalse(th.tryStart("h/mock-scam/b", "h")) // same host still in flight
        assertTrue(th.tryStart("b.com", "b.com"))
        th.finish("h")
        assertTrue(th.tryStart("h/mock-scam/b", "h"))
    }

    @Test fun blockGateNoRelaunchWithinCooldownOrWhileShowing() {
        val g = BlockGate(5_000) { clock }
        assertTrue(g.tryLaunch("evil.com", "evil.com"))
        g.onShown("evil.com")
        clock += 10_000
        assertFalse(g.tryLaunch("evil.com", "evil.com")) // already showing
        g.onClosed("evil.com", suppressMs = 3_000)
        assertFalse(g.tryLaunch("evil.com", "evil.com")) // browser going back
        clock += 3_000
        assertTrue(g.tryLaunch("evil.com", "evil.com"))
        assertFalse(g.tryLaunch("evil.com", "evil.com")) // cooldown
        assertTrue(g.tryLaunch("other.com", "other.com"))
    }

    @Test fun hiddenBlockScreenMayReopen() {
        val g = BlockGate(5_000) { clock }
        assertTrue(g.tryLaunch("evil.com", "evil.com"))
        g.onShown("evil.com")
        g.onClosed("evil.com", suppressMs = 0) // user pressed Home
        clock += 5_000
        assertTrue(g.tryLaunch("evil.com", "evil.com"))
    }
}

class DefangUrlTest {
    @Test fun defangsHostKeepsPath() {
        assertEquals("tamm-pay[.]net/fine?id=1", Defang.defangUrl("https://tamm-pay.net/fine?id=1"))
        assertEquals("10[.]0[.]2[.]2:8011/mock-scam/tamm-fine", Defang.defangUrl("http://10.0.2.2:8011/mock-scam/tamm-fine"))
        assertEquals("example[.]com", Defang.defangUrl("https://example.com/"))
        assertTrue(Defang.defangUrl("https://a.com/" + "x".repeat(100)).endsWith("…"))
    }
}
