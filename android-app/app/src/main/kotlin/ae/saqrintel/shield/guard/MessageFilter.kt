package ae.saqrintel.shield.guard

import ae.saqrintel.shield.data.OfficialDomains
import java.util.Locale

/**
 * On-device gate for the message guard. Pure Kotlin (unit-tested).
 *
 * A notification's text is sent to the SAQR server ONLY when it contains:
 *  1. a link / domain that is not an official UAE domain, or
 *  2. a phone number together with a claim or lure (police, fine, bank, prize, parcel...), or
 *  3. a request to send / share / enter a code, OTP, PIN, CVV, password or card details
 *     ("never share your OTP" style advice is not a request).
 * Ordinary chat never leaves the phone. Before sending, standalone 4-8 digit codes are masked.
 */
object MessageFilter {

    enum class Trigger { LINK, PHONE_WITH_LURE, CODE_REQUEST }

    sealed interface Decision {
        data class Send(val triggers: Set<Trigger>, val domains: List<String>) : Decision
        data class Skip(val reason: String) : Decision
    }

    // ---------------------------------------------------------------------------- normalising

    private val INVISIBLE = Regex("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF\\u00AD]")

    /** Western digits, invisible characters removed, defanged dots restored, whitespace collapsed. */
    fun normalise(text: String): String {
        val sb = StringBuilder(text.length)
        for (ch in text) {
            sb.append(
                when (ch) {
                    in '٠'..'٩' -> '0' + (ch - '٠')
                    in '۰'..'۹' -> '0' + (ch - '۰')
                    else -> ch
                },
            )
        }
        return sb.toString()
            .replace(INVISIBLE, "")
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace(Regex("[ \\t\\u00A0]+"), " ")
            .trim()
    }

    // ---------------------------------------------------------------------------- links

    private val SCHEME_URL = Regex("(?i)\\b(?:https?|hxxps?)://([^\\s/?#<>\"'()]+)")
    private val WWW_URL = Regex("(?i)(?<![\\p{L}\\p{N}.@-])(www\\.[^\\s/?#<>\"'()]+)")
    private val BARE_DOMAIN = Regex(
        "(?i)(?<![\\p{L}\\p{N}@._-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+([a-z]{2,24}))(?![\\p{L}\\p{N}_-])(/)?",
    )

    /** TLDs accepted for a bare domain (no scheme, no www). Keeps "ok.see you" out. */
    private val TLDS = setOf(
        "com", "net", "org", "info", "biz", "xyz", "top", "shop", "online", "site", "live", "app", "io", "co",
        "cc", "ly", "ink", "vip", "club", "icu", "buzz", "link", "click", "pw", "tk", "ml", "ga", "cf", "gq",
        "ru", "cn", "pk", "store", "support", "services", "help", "pay", "gov", "ae", "abudhabi", "dubai", "sa",
        "qa", "om", "kw", "bh", "eg", "uk", "de", "fr", "tv", "ws", "su", "fm", "gl", "gg", "ai", "sh", "lat",
        "cfd", "sbs", "bond", "rest", "monster", "quest", "cyou", "mobi", "asia", "work", "world", "today",
        "tech", "space", "website", "fun", "life", "pro", "page", "dev", "cloud", "email", "digital", "network",
        "center", "agency", "news", "win", "bid", "loan", "date", "review", "party", "trade", "science", "men",
        "cam", "uno", "beauty", "hair", "skin", "makeup", "autos", "boats", "homes", "yachts", "motorcycles",
        "ir", "tr", "ng", "ke", "ph", "id", "vn", "th", "br", "mx", "ar", "cl", "es", "pt", "nl", "pl", "ua",
        "kz", "uz", "az", "ge", "am", "by", "md", "lv", "lt", "ee", "cz", "sk", "hu", "ro", "bg", "gr", "cy",
        "il", "jo", "lb", "iq", "sy", "ye", "ma", "dz", "tn", "ly", "sd", "ps", "au", "nz", "ca", "jp", "kr",
        "hk", "tw", "sg", "my", "lk", "bd", "np", "ms", "vg", "ac", "re", "la", "nu", "mn",
        // ambiguous English words: accepted only with a path (see AMBIGUOUS_TLDS)
        "in", "me", "to", "it", "at", "be", "do", "go", "no", "us", "is", "so",
    )
    private val AMBIGUOUS_TLDS = setOf("in", "me", "to", "it", "at", "be", "do", "go", "no", "us", "is", "so", "my", "am", "by", "id")

    /** Hosts of the links in [text] (lower-case, de-duplicated, in order). */
    fun findDomains(text: String): List<String> {
        val t = normalise(text)
        val out = LinkedHashSet<String>()
        SCHEME_URL.findAll(t).forEach { m -> OfficialDomains.normaliseHost(m.groupValues[1])?.let(out::add) }
        WWW_URL.findAll(t).forEach { m -> OfficialDomains.normaliseHost(m.groupValues[1])?.let(out::add) }
        // Remove the URLs already found so their hosts are not matched again as bare domains.
        val rest = t.replace(SCHEME_URL, " ").replace(WWW_URL, " ")
        BARE_DOMAIN.findAll(rest).forEach { m ->
            val host = m.groupValues[1].lowercase(Locale.ROOT)
            val tld = m.groupValues[2].lowercase(Locale.ROOT)
            val hasPath = m.groupValues[3].isNotEmpty()
            if (tld in TLDS && (tld !in AMBIGUOUS_TLDS || hasPath)) {
                OfficialDomains.normaliseHost(host)?.let(out::add)
            }
        }
        return out.filter { it.contains('.') }
    }

    // ---------------------------------------------------------------------------- phone numbers

    private val PHONE = Regex("(?<![\\d+])(?:\\+|00)?\\d[\\d \\-]{5,16}\\d(?!\\d)")
    private val DATE_LIKE = Regex("^\\d{1,4}[-/ ]\\d{1,2}[-/ ]\\d{1,4}$")

    fun hasPhoneNumber(text: String): Boolean = PHONE.findAll(normalise(text)).any { m ->
        val digits = m.value.count { it.isDigit() }
        digits in 7..15 && !DATE_LIKE.matches(m.value.trim())
    }

    private const val B = "(?<![\\p{L}\\p{N}])"
    private const val E = "(?![\\p{L}\\p{N}'’])"

    private val LURE_EN = Regex(
        "(?i)$B(?:police|fines?|penalty|penalties|violations?|tamm|bank|banking|account|suspended|blocked|locked|" +
            "frozen|deactivated|verify|verification|kyc|prize|winner|won|reward|refund|cashback|parcel|package|" +
            "shipment|delivery|courier|customs|emirates post|uae ?pass|emirates id|visa|residency|salik|etisalat|" +
            "du|adcb|fab|urgent|urgently|immediately|expires?|expired|last chance|claim|lottery|investment|profit|" +
            "job offer|ministry|court|arrest|legal action|unpaid|overdue|outstanding)$E",
    )
    private val LURE_AR = Regex(
        "الشرطة|شرطة|مخالفة|مخالفات|غرامة|غرامات|الغرامة|البنك|بنك|حسابك|الحساب|بطاقتك|البطاقة|موقوف|إيقاف|ايقاف|" +
            "تجميد|محظور|تعليق|جائزة|الجائزة|ربحت|فزت|مبروك|استرداد|طرد|شحنة|الشحنة|بريد الإمارات|الهوية|الإقامة|" +
            "تحديث بيانات|عاجل|فوراً|فورا|سالك|اتصالات|مستحقة|متأخرة|المحكمة|القبض",
    )

    fun hasLure(text: String): Boolean {
        val t = normalise(text)
        return LURE_EN.containsMatchIn(t) || LURE_AR.containsMatchIn(t)
    }

    // ---------------------------------------------------------------------------- code requests

    private const val GAP = "[^.!?\\n؟]{0,40}?"

    // Hand-over verbs (the code goes to someone) vs self-entry verbs (you type it somewhere).
    private const val HANDOVER_EN = "send|share|give|tell|provide|forward|reply(?: with)?|text|read out|confirm|submit"
    private const val SELF_EN = "enter|type|input|key in"
    private const val OBJECT_EN =
        "otp|one[- ]time (?:password|code|pin)|verification code|security code|activation code|code|pin|cvv|cvc|" +
            "card number|card details|card|password|passcode"
    private val HANDOVER_EN_RE = Regex("(?i)$B(?:$HANDOVER_EN)$E$GAP$B(?:$OBJECT_EN)$E")
    private val SELF_EN_RE = Regex("(?i)$B(?:$SELF_EN)$E$GAP$B(?:$OBJECT_EN)$E")
    private val NEGATION_EN = Regex(
        "(?i)$B(?:never|not|don'?t|dont|do not|no one|nobody|won'?t|will never|must not|should not|cannot|can'?t|avoid)$E",
    )

    private const val OBJECT_AR =
        "رمز|الرمز|رمزك|كود|الكود|otp|الرقم السري|رقمك السري|كلمة المرور|كلمة السر|البطاقة|بطاقتك|رقم البطاقة|cvv"
    private const val HANDOVER_AR =
        "أرسل|ارسل|ابعث|ابعت|شارك|أعطني|اعطني|أعطنا|اعطنا|زودني|زودنا|زوّدنا|أخبرني|اخبرني|قل لي"
    private const val SELF_AR = "أدخل|ادخل|اكتب"
    private const val REQUEST_WORD_AR = "يرجى|الرجاء|رجاء|نرجو|يجب|عليك|قم ب|قم"
    private const val VERBAL_NOUN_AR = "إرسال|ارسال|مشاركة|تزويدنا|إدخال|ادخال|كتابة"
    private val HANDOVER_AR_RE =
        Regex("(?i)(?<!\\p{L})[وف]?(?:$HANDOVER_AR)(?:ي|وا|ه|ها)?(?!\\p{L})$GAP(?:$OBJECT_AR)")
    private val SELF_AR_RE = Regex("(?i)(?<!\\p{L})[وف]?(?:$SELF_AR)(?:ي|وا)?(?!\\p{L})$GAP(?:$OBJECT_AR)")
    private val REQUEST_AR_RE = Regex("(?i)(?:$REQUEST_WORD_AR)[^.!?\\n؟]{0,20}?(?:$VERBAL_NOUN_AR)$GAP(?:$OBJECT_AR)")
    private val NEGATION_AR = Regex("(?<!\\p{L})(?:لا|لن|عدم|أبدا|أبداً|ابدا|ابداً|إياك|احذر|يحذر|تحذير)(?!\\p{L})")

    private fun negated(t: String, m: MatchResult, negation: Regex): Boolean {
        // The sentence part just before the request, plus the request itself ("يرجى عدم مشاركة الرمز").
        val start = m.range.first
        var from = (start - 30).coerceAtLeast(0)
        val boundary = t.lastIndexOfAny(charArrayOf('.', '!', '?', '\n', '؟'), start - 1)
        if (boundary >= from) from = boundary + 1
        return negation.containsMatchIn(t.substring(from, m.range.last + 1))
    }

    private fun anyRequest(t: String, re: Regex, negation: Regex) =
        re.findAll(t).any { !negated(t, it, negation) }

    private fun hasAdvice(t: String): Boolean =
        listOf(HANDOVER_EN_RE, SELF_EN_RE).any { re -> re.findAll(t).any { negated(t, it, NEGATION_EN) } } ||
            listOf(HANDOVER_AR_RE, REQUEST_AR_RE).any { re -> re.findAll(t).any { negated(t, it, NEGATION_AR) } }

    /**
     * True when the text asks the reader to hand over or type a code / PIN / card detail.
     * A hand-over request always counts. A self-entry request ("Enter OTP 1234") does not count
     * when the same text also warns not to share it: that is a genuine OTP notice.
     */
    fun hasCodeRequest(text: String): Boolean {
        val t = normalise(text)
        val handover = anyRequest(t, HANDOVER_EN_RE, NEGATION_EN) ||
            anyRequest(t, HANDOVER_AR_RE, NEGATION_AR) ||
            anyRequest(t, REQUEST_AR_RE, NEGATION_AR)
        if (handover) return true
        val self = anyRequest(t, SELF_EN_RE, NEGATION_EN) || anyRequest(t, SELF_AR_RE, NEGATION_AR)
        return self && !hasAdvice(t)
    }

    // ---------------------------------------------------------------------------- decision

    fun decide(text: String?): Decision {
        val t = text?.let(::normalise).orEmpty()
        if (t.length < 8) return Decision.Skip("too_short")
        val triggers = mutableSetOf<Trigger>()
        val domains = findDomains(t)
        val unofficial = domains.filterNot { OfficialDomains.isOfficial(it) }
        if (unofficial.isNotEmpty()) triggers += Trigger.LINK
        if (hasPhoneNumber(t) && hasLure(t)) triggers += Trigger.PHONE_WITH_LURE
        if (hasCodeRequest(t)) triggers += Trigger.CODE_REQUEST
        return when {
            triggers.isNotEmpty() -> Decision.Send(triggers, domains)
            domains.isNotEmpty() -> Decision.Skip("official_links_only")
            else -> Decision.Skip("no_signal")
        }
    }

    // ---------------------------------------------------------------------------- privacy

    private val STANDALONE_CODE = Regex("(?<![\\d+])(?<![\\d+][ -])\\d{4,8}(?![ -]?\\d)")

    /**
     * The text actually sent: normalised, standalone 4-8 digit codes (OTPs, PINs) masked as ••••,
     * phone numbers (grouped or 9+ digits) kept so the server can check them.
     */
    fun prepareForServer(text: String): String =
        normalise(text).replace(STANDALONE_CODE, "••••").take(4000)
}
