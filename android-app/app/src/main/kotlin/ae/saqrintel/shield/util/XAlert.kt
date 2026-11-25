package ae.saqrintel.shield.util

import ae.saqrintel.shield.data.Reason
import ae.saqrintel.shield.data.ScanKind
import ae.saqrintel.shield.data.VerdictInfo
import android.content.Intent
import androidx.core.net.toUri
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * "Warn others on X": same EN / AR templates as the web app (frontend/src/lib/share.ts
 * buildXDraft, REASON_BY_FLAG, ENTITY_AR, xLength). Offered only when [VerdictInfo.xEligible].
 */
object XAlert {
    const val X_LIMIT = 280

    /** Arabic names for the entities the backend reports in English. */
    val ENTITY_AR: Map<String, String> = mapOf(
        "Abu Dhabi Police" to "شرطة أبوظبي",
        "TAMM Abu Dhabi" to "منصة تم",
        "Emirates Post" to "بريد الإمارات",
        "e& (Etisalat)" to "اتصالات",
        "du" to "دو",
        "UAE PASS" to "UAE PASS",
        "First Abu Dhabi Bank (FAB)" to "بنك أبوظبي الأول",
        "ADCB" to "بنك أبوظبي التجاري",
    )

    private fun r(en: String, ar: String) = en to ar

    /** Plain-language reason per backend flag code (ported 1:1 from share.ts). */
    val REASON_BY_FLAG: Map<String, Pair<String, String>> = mapOf(
        "CREDENTIAL_HARVESTING" to r("it asks for card and OTP details", "يطلب بيانات البطاقة ورمز التحقق"),
        "NEWLY_REGISTERED" to r("the site was created only hours ago", "أُنشئ الموقع قبل ساعات فقط"),
        "KNOWN_SYNDICATE_INFRA" to r("it is linked to a known scam network", "مرتبط بشبكة احتيال معروفة"),
        "UNOFFICIAL_DOMAIN_ON_LISTING" to r("a fake Google Maps listing", "إدراج مزيف على خرائط جوجل"),
        "INSTITUTION_MESSAGING_LINK" to r(
            "a fake Google Maps listing that links to a WhatsApp chat or social page",
            "إدراج مزيف على خرائط جوجل يربط بمحادثة واتساب أو صفحة تواصل اجتماعي",
        ),
        "FOREIGN_NUMBER_FOR_INSTITUTION" to r("a foreign phone number for a UAE institution", "رقم هاتف أجنبي لجهة إماراتية"),
        "HOMOGLYPH_SPOOF" to r("look-alike letters in the web address", "أحرف مشابهة في عنوان الموقع"),
        "BRAND_IMPERSONATION" to r("it is not the official website", "ليس الموقع الرسمي"),
        "TYPOSQUAT" to r("a misspelled copy of the official address", "نسخة بأخطاء إملائية من العنوان الرسمي"),
        "TLD_SWAP" to r("the official name with the wrong ending", "الاسم الرسمي بامتداد خاطئ"),
        "CLOAKING" to r("it hides from security scanners", "يتخفّى من أنظمة الفحص الأمني"),
        "REDIRECTS_TO_FLAGGED" to r("the link secretly leads to a dangerous website", "الرابط يقود خفيةً إلى موقع خطير"),
        "URL_SHORTENER" to r("a shortened link hides the real address", "رابط مختصر يخفي العنوان الحقيقي"),
        "PROVIDER_PHISHING_WARNING" to r(
            "its hosting provider already shows a phishing warning on it",
            "مزود الاستضافة يعرض عليه تحذيراً من التصيّد",
        ),
        "SHORTLINK_DISABLED" to r(
            "the link-shortening service has disabled this link for abuse",
            "خدمة اختصار الروابط عطّلت هذا الرابط بسبب إساءة الاستخدام",
        ),
        "FORM_SERVICE_CREDENTIALS" to r(
            "it sends passwords or card details to a third-party form service",
            "يرسل كلمات المرور أو بيانات البطاقة إلى خدمة نماذج خارجية",
        ),
        "BRAND_LOGIN_PAGE" to r(
            "a log-in page using a known brand's name on an unrelated site",
            "صفحة تسجيل دخول تحمل اسم جهة معروفة على موقع لا يتبعها",
        ),
        "FORM_SERVICE_LOGIN" to r(
            "a sign-in page whose form goes to a website-builder form service",
            "صفحة تسجيل دخول يُرسل نموذجها إلى خدمة نماذج خارجية",
        ),
        "BRAND_PRIZE_PAGE" to r(
            "a known brand's name with prize or free-gift bait on a free website",
            "اسم جهة معروفة مع إغراء بجوائز أو هدايا على موقع مجاني لا يتبعها",
        ),
        "AI_NEW_DOMAIN" to r("a brand-new domain whose address looks like phishing", "نطاق حديث جداً وعنوانه يشبه مواقع التصيّد"),
        "SITE_TAKEN_DOWN" to r(
            "the site has already vanished and its address looks like phishing",
            "الموقع اختفى بالفعل وعنوانه يشبه مواقع التصيّد",
        ),
        "CERT_RENEWED" to r("its security certificate was renewed very recently", "شهادة الأمان جُدّدت حديثاً جداً"),
        "REDIRECT_CHAIN" to r("it passes through hidden redirects", "يمر عبر تحويلات مخفية"),
        "YOUNG_DOMAIN" to r("a very new website", "موقع حديث جداً"),
        "URGENCY_PRESSURE" to r("fake deadlines and threats", "مهل وتهديدات مزيفة"),
        "SUSPICIOUS_TLD" to r("an unusual web address", "عنوان موقع غير مألوف"),
        "KNOWN_PHISHING_LINK" to r("it links to a known phishing website", "يحتوي على رابط لموقع تصيّد معروف"),
        "LINK_HIGH_RISK" to r("it links to a scam website", "يحتوي على رابط لموقع احتيالي"),
        "CAMPAIGN_IOC_MATCH" to r("it is part of a scam wave spreading now", "جزء من موجة احتيال منتشرة الآن"),
        "IDN_MIXED_SCRIPT" to r("look-alike letters in the sender's address", "أحرف مشابهة في عنوان المرسل"),
        "DISPLAY_NAME_CONFUSABLE" to r("look-alike letters hiding a fake brand name", "أحرف مشابهة تخفي اسماً تجارياً مزيفاً"),
        "BIDI_OVERRIDE" to r("a hidden text-direction trick", "خدعة مخفية في اتجاه النص"),
        "DANGEROUS_ATTACHMENT" to r("a dangerous attached file", "ملف مرفق خطير"),
        "SENDER_LOOKALIKE" to r("a fake copy of the official sender address", "نسخة مزيفة من عنوان المرسل الرسمي"),
        "FREEMAIL_BRAND_SENDER" to r("it comes from a free email account, not the company", "أُرسل من حساب بريد مجاني وليس من الجهة نفسها"),
        "DISPLAY_NAME_BRAND_SPOOF" to r("a fake sender name", "اسم مرسل مزيف"),
        "LINK_TEXT_MISMATCH" to r("links that open a different website than shown", "روابط تفتح موقعاً غير الظاهر"),
        "DMARC_FAIL" to r("the sender's address is forged", "عنوان المرسل مزوّر"),
        "INVISIBLE_IN_TOKEN" to r("invisible characters hidden inside words or links", "أحرف غير مرئية مخفية داخل الكلمات أو الروابط"),
        "PUNYCODE_DOMAIN" to r("an unusual encoded web address", "عنوان ويب مُرمّز بشكل غير معتاد"),
        "FANCY_UNICODE" to r("text written in unusual styled letters", "نص مكتوب بأحرف مزخرفة غير معتادة"),
        "DISPLAY_NAME_ADDRESS_SPOOF" to r("the sender name shows a fake email address", "اسم المرسل يعرض عنوان بريد مزيفاً"),
        "REPLY_TO_FREEMAIL_BRAND" to r("replies go to a free email account", "الردود تذهب إلى حساب بريد مجاني"),
        "REPLY_TO_MISMATCH" to r("replies go to a different address", "الردود تذهب إلى عنوان مختلف"),
        "RETURN_PATH_MISMATCH" to r("its hidden return address belongs to someone else", "عنوان الإرجاع المخفي يتبع جهة أخرى"),
        "SENDER_NEW_DOMAIN" to r("the sender's domain was created days ago", "أُنشئ نطاق المرسل قبل أيام"),
        "CALLBACK_MOBILE_FOR_INSTITUTION" to r(
            "it gives a personal mobile number for an institution",
            "يذكر رقم هاتف متحرك شخصي باسم جهة رسمية",
        ),
        "CALLBACK_FOREIGN_FOR_INSTITUTION" to r(
            "it gives a foreign phone number for a UAE institution",
            "يذكر رقم هاتف أجنبياً باسم جهة إماراتية",
        ),
        "SENDER_NO_MX" to r("the sender's domain has no mail server", "نطاق المرسل لا يملك خادم بريد"),
        "TLS_INVALID" to r("its security certificate is not valid", "شهادة الأمان الخاصة به غير صالحة"),
        "MSG_SHORTENER_FOR_INSTITUTION" to r("it names a known sender but hides its link behind a public link shortener", "تذكر جهة معروفة لكنها تُخفي الرابط خلف خدمة اختصار روابط عامة"),
        "MSG_LOOKALIKE_LETTERS" to r("it writes ordinary words with look-alike foreign letters to slip past filters", "تكتب كلمات عادية بأحرف أجنبية شبيهة لتجاوز الفلاتر"),
        "MSG_CALLBACK_PRESSURE" to r("it pushes you to call a phone number about a problem with your account", "تدفعك للاتصال برقم هاتف بسبب مشكلة في حسابك"),
        "MSG_JOB_LURE" to r("an unexpected job offer with easy pay for little work", "عرض عمل غير متوقع بأجر سهل مقابل عمل بسيط"),
        "MSG_NEW_NUMBER_LURE" to r("someone claims to be family or a friend on a new number", "شخص يدّعي أنه من العائلة أو الأصدقاء من رقم جديد"),
        "MSG_GIFT_CARD_REQUEST" to r("it asks you to buy gift cards and send the codes", "تطلب شراء بطاقات هدايا وإرسال رموزها"),
        "MSG_INVESTMENT_LURE" to r("it promises guaranteed or very high returns", "تعد بأرباح مضمونة أو مرتفعة جداً"),
        "MSG_PRESSURE_UNOFFICIAL_LINK" to r("it uses a known name, pressures you and links to a website that is not theirs", "تستخدم اسماً معروفاً وتضغط عليك وتوجّهك إلى موقع لا يتبعه"),
        "MSG_SCAM_LINK" to r("its link leads to a scam website", "رابطها يقود إلى موقع احتيالي"),
        "MSG_SUSPICIOUS_LINK" to r("its link leads to a suspicious website", "رابطها يقود إلى موقع مشبوه"),
        "MSG_LOOKALIKE_LINK" to r("its link imitates an official website", "رابطها يقلّد موقعاً رسمياً"),
        "MSG_CREDENTIAL_REQUEST" to r(
            "it asks you to send your OTP, PIN or card details",
            "تطلب منك إرسال رمز التحقق أو الرقم السري أو بيانات البطاقة",
        ),
        "SENDER_MOBILE_FOR_INSTITUTION" to r(
            "an institution would never text from a personal mobile",
            "الجهات الرسمية لا ترسل رسائل من أرقام شخصية",
        ),
        "SENDER_FOREIGN_FOR_INSTITUTION" to r(
            "a UAE institution would never text from a foreign number",
            "الجهات الإماراتية لا ترسل رسائل من أرقام أجنبية",
        ),
        "MSG_PHONE_LINKED_TO_SCAM" to r("its phone number is linked to known fraud", "رقم الهاتف مرتبط باحتيال معروف"),
        "OFFICIAL_SENDER_UNAUTHENTICATED" to r("it pretends to come from an official address", "يدّعي أنه صادر من عنوان رسمي"),
        "HEADERS_NOT_AVAILABLE" to r("only the visible text could be checked", "تم فحص النص الظاهر فقط"),
        "DMARC_FAIL_P_NONE" to r("the sender's address failed the domain check", "فشل عنوان المرسل في فحص النطاق"),
        "SPF_FAIL" to r("the sending server is not allowed to send for that address", "خادم الإرسال غير مخوّل بالإرسال باسم هذا العنوان"),
        "SPF_SOFTFAIL" to r(
            "the sending server is probably not allowed to send for that address",
            "خادم الإرسال على الأرجح غير مخوّل بالإرسال باسم هذا العنوان",
        ),
        "DKIM_FAIL" to r("the email's digital signature is broken", "التوقيع الرقمي للرسالة غير صالح"),
        "NO_AUTHENTICATION" to r("the sender could not be verified at all", "تعذّر التحقق من المرسل إطلاقاً"),
        "DMARC_PASS" to r("the sender's domain passed DMARC", "اجتاز نطاق المرسل فحص DMARC"),
        "ARC_PASS" to r("a trusted mail server vouched for the forwarding", "أكّد خادم بريد موثوق سلامة إعادة التوجيه"),
        "BULK_SENDER" to r("it is a newsletter or mailing-list message", "رسالة نشرة بريدية أو قائمة مراسلات"),
        "OFFICIAL_SENDER" to r("it was sent from an official address", "أُرسلت من عنوان رسمي"),
        "LINK_SUSPICIOUS" to r("its link opens a suspicious website", "رابطه يفتح موقعاً مشبوهاً"),
        "ATTACHMENT_ARCHIVE" to r("a compressed file is attached", "مرفق ملف مضغوط"),
        "CAMPAIGN_LURE_MATCH" to r("it uses the wording of a known scam wave", "يستخدم صياغة موجة احتيال معروفة"),
        "CREDENTIAL_REQUEST" to r("it asks for your password or card details", "يطلب كلمة المرور أو بيانات البطاقة"),
        "PAYMENT_REQUEST" to r("it asks you to pay a fee", "يطلب منك دفع رسوم"),
        "URGENCY_LANGUAGE" to r("fake deadlines and threats", "مهل وتهديدات مزيفة"),
        "BRAND_MENTION" to r("it uses a well-known company's name", "يستخدم اسم جهة معروفة"),
        "USER_MODEL_SCAM" to r("it looks like emails you marked as scams", "يشبه رسائل صنّفتها سابقاً كاحتيال"),
        "USER_MODEL_TRUSTED" to r("it looks like emails you marked as safe", "تشبه رسائل صنّفتها كآمنة"),
    )
    val DEFAULT_REASON: Pair<String, String> = "it fails official verification" to "لم يجتز التحقق الرسمي"

    /** Highest-points flag that has a plain reason, else [DEFAULT_REASON] (same as share.ts reasonFor). */
    fun reasonFor(flags: List<Reason>): Pair<String, String> =
        flags.sortedByDescending { it.points }.firstNotNullOfOrNull { f -> f.code?.let { REASON_BY_FLAG[it] } }
            ?: DEFAULT_REASON

    fun entityAr(info: VerdictInfo): String? =
        info.entityAr ?: info.entityEn?.let { ENTITY_AR[it] }

    /**
     * The X post text. Uses share.ts templates; if the weighted length passes [X_LIMIT] the entity
     * is dropped, then the domain is shortened, so the intent never opens with an over-long post.
     */
    fun buildDraft(info: VerdictInfo, arabic: Boolean): String {
        val reason = reasonFor(info.allFlags.ifEmpty { info.reasons })
        val domain = info.domain?.let(Defang::defang)
        val entity = if (arabic) entityAr(info) else info.entityEn
        var text = template(info.kind, arabic, entity, domain, if (arabic) reason.second else reason.first)
        if (xLength(text) > X_LIMIT) text = template(info.kind, arabic, null, domain, if (arabic) reason.second else reason.first)
        if (xLength(text) > X_LIMIT) {
            val d = DEFAULT_REASON
            text = template(info.kind, arabic, null, domain?.take(60), if (arabic) d.second else d.first)
        }
        return text
    }

    internal fun template(kind: ScanKind, arabic: Boolean, entity: String?, masked: String?, reason: String): String {
        val dom = masked?.let { " ($it)" }.orEmpty()
        if (arabic) {
            val what = when (kind) {
                ScanKind.EMAIL -> "رسائل بريد مزيفة"
                ScanKind.MESSAGE -> "رسائل نصية مزيفة"
                else -> "روابط مزيفة"
            }
            val who = if (entity != null) "$what تنتحل صفة $entity" else what
            return "⚠️ تحذير احتيال في أبوظبي: احذروا $who$dom. " +
                "علامة الخطر: $reason. تحقّقوا قبل الضغط وأبلغوا أمان 8002626 / رسالة 2828. " +
                "#أبوظبي #الأمن_السيبراني #Aman8002626"
        }
        val noun = when (kind) {
            ScanKind.EMAIL -> "emails"
            ScanKind.MESSAGE -> "text messages"
            else -> "links"
        }
        val who = if (entity != null) "fake $entity $noun" else "fake $noun"
        return "⚠️ Fraud Alert in Abu Dhabi: Watch out for $who$dom. " +
            "Red flag: $reason. Verify before clicking & report to Aman 8002626 / SMS 2828. " +
            "#AbuDhabi #CyberSafety #Aman8002626"
    }

    private val LIGHT_RANGES = listOf(0..4351, 8192..8205, 8208..8223, 8242..8247)

    private fun isPictographic(cp: Int): Boolean =
        cp in 0x2300..0x23FF || cp in 0x2600..0x27BF || cp in 0x2B00..0x2BFF || cp in 0x1F000..0x1FAFF

    /** X's weighted length: Latin/Arabic count 1; emoji (one grapheme) and CJK count 2. */
    fun xLength(text: String): Int {
        var total = 0
        var i = 0
        var inEmoji = false
        while (i < text.length) {
            val cp = text.codePointAt(i)
            i += Character.charCount(cp)
            // Variation selector / skin tone: part of the emoji grapheme just counted.
            if (inEmoji && (cp == 0xFE0F || cp in 0x1F3FB..0x1F3FF)) continue
            if (inEmoji && cp == 0x200D) {
                // ZWJ joins the next pictograph into the same grapheme.
                if (i < text.length) i += Character.charCount(text.codePointAt(i))
                continue
            }
            if (isPictographic(cp)) {
                total += 2
                inEmoji = true
                continue
            }
            inEmoji = false
            total += if (LIGHT_RANGES.any { cp in it }) 1 else 2
        }
        return total
    }

    fun intentUrl(text: String): String =
        "https://x.com/intent/post?text=" + URLEncoder.encode(text, StandardCharsets.UTF_8.name()).replace("+", "%20")

    fun intent(text: String): Intent =
        Intent(Intent.ACTION_VIEW, intentUrl(text).toUri()).addCategory(Intent.CATEGORY_BROWSABLE)
}
