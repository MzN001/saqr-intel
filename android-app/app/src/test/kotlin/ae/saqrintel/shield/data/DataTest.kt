package ae.saqrintel.shield.data

import ae.saqrintel.shield.guard.AlertNotifier
import ae.saqrintel.shield.guard.GuardEngine
import ae.saqrintel.shield.guard.GuardSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OfficialDomainsTest {
    @Test fun exactAndSubdomainMatch() {
        assertTrue(OfficialDomains.isOfficial("adpolice.gov.ae"))
        assertTrue(OfficialDomains.isOfficial("https://www.adpolice.gov.ae/en/fines?x=1"))
        assertTrue(OfficialDomains.isOfficial("www.tamm.abudhabi"))
        assertTrue(OfficialDomains.isOfficial("ADCB.com."))
        assertTrue(OfficialDomains.isOfficial("anything.gov.ae"))
        assertTrue(OfficialDomains.isOfficial("du.ae"))
    }

    @Test fun lookAlikesDoNotMatch() {
        assertFalse(OfficialDomains.isOfficial("gov.ae.evil.com"))
        assertFalse(OfficialDomains.isOfficial("adpolice.gov.ae.evil.com"))
        assertFalse(OfficialDomains.isOfficial("myadcb.com"))
        assertFalse(OfficialDomains.isOfficial("tamm-abudhabi.com"))
        assertFalse(OfficialDomains.isOfficial("fakedu.ae"))
        assertFalse(OfficialDomains.isOfficial("gov.ae"))
        assertFalse(OfficialDomains.isOfficial("https://user@evil.com/adcb.com"))
        assertFalse(OfficialDomains.isOfficial(null))
    }
}

class AutoRouterTest {
    @Test fun routes() {
        assertEquals(ScanRoute.WEB, AutoRouter.route("https://tamm-smart-pay.net/fine"))
        assertEquals(ScanRoute.WEB, AutoRouter.route("tamm-smart-pay.net"))
        assertEquals(ScanRoute.MAPS, AutoRouter.route("https://maps.app.goo.gl/AbCdEf123"))
        assertEquals(ScanRoute.MAPS, AutoRouter.route("https://www.google.com/maps/place/Abu+Dhabi+Police"))
        assertEquals(ScanRoute.PHONE, AutoRouter.route("+971 50 000 7781"))
        assertEquals(ScanRoute.PHONE, AutoRouter.route("800 2626"))
        assertEquals(ScanRoute.EMAIL, AutoRouter.route("From: FAB <a@b.com>\nSubject: Account locked\n\nHello"))
        assertEquals(ScanRoute.MESSAGE, AutoRouter.route("TAMM: unpaid fine, pay at tamm-pay.net now"))
        assertEquals(ScanRoute.MESSAGE, AutoRouter.route("someone@example.com"))
    }
}

class SettingsValidationTest {
    @Test fun httpsRequired() {
        assertEquals("https://saqr-intel-api.onrender.com", Settings.validateBaseUrl(" https://saqr-intel-api.onrender.com/ ", false))
        assertNull(Settings.validateBaseUrl("http://saqr-intel-api.onrender.com", false))
        assertNull(Settings.validateBaseUrl("http://10.0.2.2:8011", false))
        assertEquals("http://10.0.2.2:8011", Settings.validateBaseUrl("http://10.0.2.2:8011", true))
        assertNull(Settings.validateBaseUrl("http://192.168.1.20:8011", true))
        assertNull(Settings.validateBaseUrl("ftp://x.com", true))
        assertNull(Settings.validateBaseUrl("https://x.com/?a=1", true))
        assertNull(Settings.validateBaseUrl("not a url", true))
    }

    @Test fun reporterIdShape() {
        assertTrue(Regex("^r-[0-9a-f]{32}$").matches(Settings.newReporterId()))
    }
}

class ParsingTest {
    @Test fun messageResponseWithMissingAndExtraFields() {
        val json = """
            {"scan_id":"MSG-1","kind":"message","verdict":"HIGH-RISK SCAM","risk_score":96.0,
             "impersonated_entity":"TAMM Abu Dhabi","brand_new_field":{"x":[1,2]},
             "red_flags":[{"code":"MSG_SCAM_LINK","severity":"critical","points":40,"en":"Scam link","ar":"رابط احتيالي"},
                          {"code":"URGENCY","points":0,"en":"weak"},
                          {"code":"MSG_CREDENTIAL_REQUEST","points":30,"en":"Asks for OTP"}],
             "message":{"excerpt":"TAMM ••••","credential_requests":["OTP"]},
             "links":[{"url":"https://tamm-smart-pay.net/fine","domain":"tamm-smart-pay.net","official":false,
                       "scanned":true,"verdict":"HIGH-RISK SCAM","risk_score":92},
                      {"domain":"tamm.abudhabi","official":true}],
             "phones":[{"masked":"+971 50 ••• 7781","level":"danger"}]}
        """.trimIndent()
        val info = ApiJson.decodeFromString(ScanResponse.serializer(), json).toVerdictInfo(ScanKind.MESSAGE)
        assertEquals(Verdict.SCAM, info.verdict)
        assertEquals(96, info.score)
        assertEquals("tamm-smart-pay.net", info.domain)
        assertEquals(listOf("MSG_SCAM_LINK", "MSG_CREDENTIAL_REQUEST"), info.reasons.map { it.code })
        assertEquals("Asks for OTP", info.reasons[1].ar) // missing Arabic falls back to English
        assertTrue(info.credentialRequest)
        assertTrue(info.xEligible)
        assertEquals(2, info.links.size)
        assertEquals(1, info.phones.size)
    }

    @Test fun minimalAndNullResponses() {
        val info = ApiJson.decodeFromString(ScanResponse.serializer(), """{"risk_score":null,"links":null}""")
            .toVerdictInfo(ScanKind.WEB)
        assertEquals(Verdict.SAFE, info.verdict)
        assertEquals(0, info.score)
        assertFalse(info.xEligible)
        val susp = ApiJson.decodeFromString(ScanResponse.serializer(), """{"verdict":"weird","risk_score":45}""")
            .toVerdictInfo(ScanKind.WEB)
        assertEquals(Verdict.SUSPICIOUS, susp.verdict)
    }

    @Test fun phoneResponse() {
        val json = """{"status":"mobile_for_institution","level":"danger","entity":{"name_en":"Abu Dhabi Police",
            "official_domains":["adpolice.gov.ae"]},"reasons":[{"code":"X","en":"Personal mobile","ar":"رقم شخصي"}],"extra":1}"""
        val info = ApiJson.decodeFromString(PhoneCheckResponse.serializer(), json).toVerdictInfo()
        assertEquals(Verdict.SCAM, info.verdict)
        assertNull(info.score)
        assertEquals("adpolice.gov.ae", info.officialDomain)
        assertFalse(info.xEligible)
    }

    @Test(expected = IllegalArgumentException::class)
    fun malformedJsonThrowsSerializationExceptionCaughtByClient() {
        ApiJson.decodeFromString(ScanResponse.serializer(), """{"risk_score":"high"""")
    }

    @Test fun fastApiErrorDetail() {
        assertEquals("No URL found", ApiClient.detailOf("""{"detail":"No URL found"}"""))
        val literal = """{"detail":[{"type":"literal_error","loc":["body","interception_channel"],"msg":"Input should be 'A'"}]}"""
        assertEquals("Input should be 'A'", ApiClient.detailOf(literal))
        assertNull(ApiClient.detailOf("<html>502</html>"))
    }

    @Test fun alertRecordKeepsNoMessageText() {
        val info = ApiJson.decodeFromString(
            ScanResponse.serializer(),
            """{"scan_id":"MSG-9","verdict":"SUSPICIOUS","risk_score":50,"message":{"excerpt":"secret text"},
               "links":[{"domain":"pay-fine.top","verdict":"SUSPICIOUS","risk_score":50}],
               "red_flags":[{"code":"A","points":10,"en":"a"},{"code":"B","points":9,"en":"b"},{"code":"C","points":8,"en":"c"}]}""",
        ).toVerdictInfo(ScanKind.MESSAGE)
        val record = AlertRecord.from(info, AlertKind.SMS)
        val stored = ApiJson.encodeToString(AlertRecord.serializer(), record)
        assertFalse(stored.contains("secret text"))
        assertEquals("pay-fine[.]top", record.label)
        assertEquals(2, record.reasonsEn.size)
        assertEquals("pay-fine.top", record.toVerdictInfo().domain)
    }
}

class GuardHelpersTest {
    @Test fun onlyNumbersAndSenderIdsLeaveThePhone() {
        assertEquals("+971 50 000 7781", GuardEngine.senderForServer("+971 50 000 7781", GuardSource.SMS))
        assertEquals("ADPolice", GuardEngine.senderForServer("ADPolice", GuardSource.SMS))
        assertNull(GuardEngine.senderForServer("Ahmed", GuardSource.SMS))
        assertNull(GuardEngine.senderForServer("Mum ❤", GuardSource.WHATSAPP))
        assertNull(GuardEngine.senderForServer("ADPolice", GuardSource.WHATSAPP))
        assertNull(GuardEngine.senderForServer(null, GuardSource.SMS))
    }

    @Test fun notificationLineFits() {
        val long = "Fake First Abu Dhabi Bank customer service link (very-long-lookalike-domain-name[.]com)"
        val fallback = "Scam link (very-long-lookalike-domain-name[.]com)"
        assertEquals(fallback, AlertNotifier.fitLine(long, fallback))
        assertEquals("ok", AlertNotifier.fitLine("ok", fallback))
        assertTrue(AlertNotifier.fitLine(long, long).length <= AlertNotifier.MAX_TEXT)
        assertEquals("TAMM", AlertNotifier.shortEntity("TAMM Abu Dhabi"))
    }
}
