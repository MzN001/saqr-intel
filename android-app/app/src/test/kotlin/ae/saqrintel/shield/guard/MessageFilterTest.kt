package ae.saqrintel.shield.guard

import ae.saqrintel.shield.guard.MessageFilter.Decision
import ae.saqrintel.shield.guard.MessageFilter.Trigger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MessageFilterTest {

    private fun sent(text: String) = MessageFilter.decide(text) is Decision.Send
    private fun triggers(text: String) = (MessageFilter.decide(text) as? Decision.Send)?.triggers.orEmpty()

    @Test fun ordinaryChatStaysOnPhone() {
        listOf(
            "Hey, are we still on for dinner tonight?",
            "ok.see you at 7",
            "Call me when you land, my number is 050 123 4567",
            "I won't be late, traffic is fine",
            "The meeting moved to 24-11-2026, room 3",
            "Can you send me the photos from yesterday?",
            "Wait...what happened?",
            "هلا، وين أنت؟ نلتقي بعد ساعة",
            "اتصل علي على 0501234567 لما توصل",
            "Thanks! The code review went well.",
        ).forEach { assertFalse("should stay on phone: $it", sent(it)) }
    }

    @Test fun scamSmsWithLinkIsSent() {
        val t = "TAMM: You have an unpaid traffic fine of AED 350. Pay now: https://tamm-smart-pay.net/fine"
        assertTrue(Trigger.LINK in triggers(t))
        assertTrue(Trigger.LINK in triggers("Your parcel is held at customs. Pay the fee at emiratespost-track.top"))
        assertTrue(Trigger.LINK in triggers("Claim your refund: bit.ly/3xYzAbc"))
        assertTrue(Trigger.LINK in triggers("Visit www.salik-refund.info today"))
    }

    @Test fun defangedAndHiddenLinksAreFound() {
        assertEquals(listOf("tamm-pay.net"), MessageFilter.findDomains("pay at tamm-pay[.]net now"))
        assertEquals(listOf("evil.com"), MessageFilter.findDomains("open evil​.com"))
    }

    @Test fun phoneWithLureIsSent() {
        val t = "Abu Dhabi Police: your fine is overdue. Call 050 000 7781 immediately to avoid arrest."
        assertTrue(Trigger.PHONE_WITH_LURE in triggers(t))
        assertTrue(Trigger.PHONE_WITH_LURE in triggers("مبروك! ربحت جائزة 50000 درهم. اتصل على ٠٥٠١٢٣٤٥٦٧"))
    }

    @Test fun codeRequestIsSent() {
        assertTrue(Trigger.CODE_REQUEST in triggers("Your card is blocked. Reply with your CVV and card number to unlock it."))
        assertTrue(Trigger.CODE_REQUEST in triggers("Please send me the 6 digit code you just received"))
        assertTrue(Trigger.CODE_REQUEST in triggers("أرسل لنا رمز التحقق الذي وصلك لتفعيل الحساب"))
        assertTrue(Trigger.CODE_REQUEST in triggers("يرجى إرسال الرمز المرسل إليك لإكمال التحديث"))
    }

    @Test fun genuineOtpAdviceIsNotARequest() {
        listOf(
            "Your OTP is 482913. Never share this code with anyone.",
            "482913 is your verification code. Do not share it. ADCB will never ask for your OTP.",
            "Enter OTP 482913 to complete your purchase. Do not share this code with anyone.",
            "رمز التحقق الخاص بك هو 4829. لا تشارك الرمز مع أي شخص.",
            "تم إرسال رمز التحقق إلى هاتفك",
            "يرجى عدم مشاركة الرمز مع أي شخص",
        ).forEach {
            assertFalse("advice is not a request: $it", MessageFilter.hasCodeRequest(it))
            assertFalse("should stay on phone: $it", sent(it))
        }
    }

    @Test fun officialOnlyLinksAreSkipped() {
        val d = MessageFilter.decide("Pay your fine securely on https://www.tamm.abudhabi/fines or adpolice.gov.ae")
        assertTrue(d is Decision.Skip)
        assertEquals("official_links_only", (d as Decision.Skip).reason)
        // A look-alike next to an official link is still sent.
        assertTrue(sent("Official: tamm.abudhabi — pay here: tamm.abudhabi.pay-fine.com"))
    }

    @Test fun codesAreMaskedBeforeSending() {
        val out = MessageFilter.prepareForServer("Send code 482913 to 800 2626 or +971 50 000 7781")
        assertFalse(out.contains("482913"))
        assertTrue(out.contains("800 2626"))
        assertTrue(out.contains("+971 50 000 7781"))
        assertEquals("رمز ••••", MessageFilter.prepareForServer("رمز ٤٨٢٩"))
    }
}
