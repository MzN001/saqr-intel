package ae.saqrintel.shield.util

import ae.saqrintel.shield.data.Reason
import ae.saqrintel.shield.data.ScanKind
import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.data.VerdictInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DefangTest {
    @Test fun defangs() {
        assertEquals("tamm-pay[.]net", Defang.defang("tamm-pay.net"))
        assertEquals("tamm-pay[.]net", Defang.defang("https://tamm-pay.net/refund?id=1"))
        assertEquals("www[.]x[.]co[.]ae", Defang.defang("HTTP://www.x.co.ae"))
        assertEquals("a.b.c", Defang.refang("a[.]b[.]c"))
    }
}

class XAlertTest {
    private fun info(
        kind: ScanKind = ScanKind.WEB,
        entity: String? = "TAMM Abu Dhabi",
        domain: String? = "tamm-smart-pay.net",
        flags: List<Reason> = listOf(Reason("TYPOSQUAT", "x", "x", 30), Reason("CREDENTIAL_HARVESTING", "y", "y", 40)),
        score: Int = 92,
        verdict: Verdict = Verdict.SCAM,
    ) = VerdictInfo(kind, "SCN-1", verdict, score, domain, entity, null, null, false, flags.take(3), flags)

    @Test fun englishTemplateMatchesWeb() {
        val t = XAlert.buildDraft(info(), arabic = false)
        assertEquals(
            "⚠️ Fraud Alert in Abu Dhabi: Watch out for fake TAMM Abu Dhabi links (tamm-smart-pay[.]net). " +
                "Red flag: it asks for card and OTP details. Verify before clicking & report to Aman 8002626 / SMS 2828. " +
                "#AbuDhabi #CyberSafety #Aman8002626",
            t,
        )
        assertTrue(XAlert.xLength(t) <= XAlert.X_LIMIT)
    }

    @Test fun arabicTemplateUsesArabicEntityAndMessageNoun() {
        val t = XAlert.buildDraft(info(kind = ScanKind.MESSAGE, domain = null), arabic = true)
        assertTrue(t.startsWith("⚠️ تحذير احتيال في أبوظبي: احذروا رسائل نصية مزيفة تنتحل صفة منصة تم. "))
        assertTrue(t.contains("علامة الخطر: يطلب بيانات البطاقة ورمز التحقق."))
        assertFalse(t.contains("("))
    }

    @Test fun reasonFallback() {
        val t = XAlert.buildDraft(info(flags = listOf(Reason("UNKNOWN_CODE", "z", "z", 50))), arabic = false)
        assertTrue(t.contains("Red flag: it fails official verification."))
    }

    @Test fun weightedLength() {
        assertEquals(2, XAlert.xLength("⚠️"))
        assertEquals(3, XAlert.xLength("abc"))
        assertEquals(4, XAlert.xLength("مرحب"))
        assertEquals(2, XAlert.xLength("中"))
    }

    @Test fun overLongPostIsShortened() {
        val longEntity = "A".repeat(150)
        val t = XAlert.buildDraft(info(entity = longEntity, domain = "x".repeat(60) + ".com"), arabic = false)
        assertTrue(XAlert.xLength(t) <= XAlert.X_LIMIT)
        assertFalse(t.contains(longEntity))
    }

    @Test fun eligibility() {
        assertTrue(info(score = 60).xEligible)
        assertFalse(info(score = 59, verdict = Verdict.SUSPICIOUS).xEligible)
        assertFalse(info(score = 80, verdict = Verdict.SAFE).xEligible)
    }

    @Test fun intentUrlEncodesText() {
        val u = XAlert.intentUrl("a b&c")
        assertEquals("https://x.com/intent/post?text=a%20b%26c", u)
    }
}
