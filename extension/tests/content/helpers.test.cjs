// Unit tests for the pure helpers of the mail content scripts (no DOM needed).
// Run: node --test extension/tests/content/
//
// The content scripts are loaded the way Chrome loads them: one shared global scope, files in the
// manifest order (lib/email_features.js, lib/campaign_match.js, content/common.js, content/gmail.js,
// content/outlook.js, content/wip.js). Without a "document" none of them touches a page.

"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { domainToASCII } = require("node:url");

const EXT = path.resolve(__dirname, "..", "..");
const REPO = path.resolve(EXT, "..");

function load() {
  const ctx = vm.createContext({ console, URL, URLSearchParams, TextEncoder, TextDecoder, crypto: globalThis.crypto, setTimeout, clearTimeout });
  ctx.globalThis = ctx;
  for (const f of ["lib/config.js", "lib/email_features.js", "lib/campaign_match.js", "content/common.js", "content/gmail.js", "content/outlook.js", "content/wip.js"]) {
    const file = path.join(EXT, f);
    if (!fs.existsSync(file)) continue; // lib/* belongs to another workstream; tolerate absence
    vm.runInContext(fs.readFileSync(file, "utf8"), ctx, { filename: file });
  }
  return ctx;
}

const G = load();
const U = G.SaqrMail.util;
const Gm = G.SaqrGmail;
const Ol = G.SaqrOutlook;
const Wip = G.SaqrWip;
const plain = (x) => JSON.parse(JSON.stringify(x)); // objects from the vm context → this realm
const codes = (fs) => plain(fs).map((f) => f.code + ":" + f.level).sort();

// ------------------------------------------------------------------------------------- links
test("unwrapLink: Google redirect, Outlook Safe Links, nesting, untouched links", () => {
  assert.equal(U.unwrapLink("https://www.google.com/url?q=https://evil.example/login?a%3D1&sa=D&source=x"), "https://evil.example/login?a=1");
  assert.equal(U.unwrapLink("https://www.google.ae/url?url=https%3A%2F%2Fx.test%2F"), "https://x.test/");
  const inner = "https://paypal-account-review.test/signin?x=1&y=2";
  const safe = "https://eur01.safelinks.protection.outlook.com/?url=" + encodeURIComponent(inner) + "&data=05%7C01&reserved=0";
  assert.equal(U.unwrapLink(safe), inner);
  const nested = "https://nam12.safelinks.protection.outlook.com/?url=" + encodeURIComponent("https://www.google.com/url?q=" + encodeURIComponent(inner));
  assert.equal(U.unwrapLink(nested), inner);
  assert.equal(U.unwrapLink("https://www.paypal.com/signin"), "https://www.paypal.com/signin");
  assert.equal(U.unwrapLink("https://www.google.com/url"), "https://www.google.com/url");
  assert.equal(U.unwrapLink("https://www.google.com/url?q=javascript:alert(1)"), "https://www.google.com/url?q=javascript:alert(1)");
  assert.equal(U.unwrapLink("https://www.google.com/search?q=https://x.test"), "https://www.google.com/search?q=https://x.test");
  assert.equal(U.unwrapLink("mailto:a@b.c"), "mailto:a@b.c");
  assert.equal(U.unwrapLink("not a url"), "not a url");
});

test("hostOf / parseAddress", () => {
  assert.equal(U.hostOf("https://WWW.Example.COM./x"), "www.example.com");
  assert.equal(U.hostOf("example.org/path"), "example.org");
  assert.equal(U.hostOf(""), "");
  assert.deepEqual(plain(U.parseAddress('"PayPal Support" <pp@gmail.com>')), { name: "PayPal Support", address: "pp@gmail.com" });
  assert.deepEqual(plain(U.parseAddress("a@b.com")), { name: "", address: "a@b.com" });
  assert.deepEqual(plain(U.parseAddress("Just A Name")), { name: "Just A Name", address: "" });
});

// ------------------------------------------------------------------------------------- Gmail ids
test("Gmail legacy hex id → decimal msg-f id (BigInt, beyond 2^53)", () => {
  assert.equal(Gm.legacyHexToMsgId("18c9a2b3c4d5e6f7"), "msg-f:" + BigInt("0x18c9a2b3c4d5e6f7").toString());
  assert.equal(Gm.legacyHexToMsgId("18c9a2b3c4d5e6f7"), "msg-f:1786137620214310647");
  assert.equal(Gm.legacyHexToMsgId("FFFFFFFFFFFFFFFF"), "msg-f:18446744073709551615");
  assert.equal(Gm.legacyHexToMsgId("0x1a"), "msg-f:26");
  for (const bad of ["", null, "xyz", "12345678901234567", "0", "-1a"]) assert.equal(Gm.legacyHexToMsgId(bad), null, String(bad));
});

test("Gmail permMsgId from data-message-id / thread id / legacy id", () => {
  assert.equal(Gm.permMsgId("#msg-f:1786137620214310647"), "msg-f:1786137620214310647");
  assert.equal(Gm.permMsgId("#msg-a:r-8270516427519016349"), "msg-a:r-8270516427519016349");
  assert.equal(Gm.permMsgId("#thread-f:1786137620214310647"), "msg-f:1786137620214310647");
  assert.equal(Gm.permMsgId("", "18c9a2b3c4d5e6f7"), "msg-f:1786137620214310647");
  assert.equal(Gm.permMsgId("#msg-f:12<script>"), null);
  assert.equal(Gm.permMsgId(null, null), null);
});

test("Gmail account index, original URL, ik extraction", () => {
  assert.equal(Gm.accountIndex("/mail/u/2/"), 2);
  assert.equal(Gm.accountIndex("/mail/u/0"), 0);
  assert.equal(Gm.accountIndex("/mail/"), 0);
  assert.equal(Gm.originalUrl(1, "a1b2c3d4e5", "msg-f:123"), "/mail/u/1/?ik=a1b2c3d4e5&view=om&permmsgid=msg-f%3A123");
  assert.equal(Gm.originalUrl(0, null, "msg-f:9"), "/mail/u/0/?view=om&permmsgid=msg-f%3A9");
  assert.equal(Gm.ikFromText("application/pdf:bill.pdf:https://mail.google.com/mail/u/0/?ui=2&ik=0a1b2c3d4e&attid=0.1&permmsgid=msg-f:1"), "0a1b2c3d4e");
  assert.equal(Gm.ikFromText("https://mail.google.com/mail/u/0/?ui=2&amp;ik=abcdef1234&amp;view=pt"), "abcdef1234");
  assert.equal(Gm.ikFromText("https://x.test/?like=1"), null);
  const script = 'var GM_START_TIME=1;var GLOBALS=[null,null,1234,"https://accounts.google.com/x?a=[1]","en",null,"a",null,"c","f00dfeed12",[1,[2,"]"]],"x"];GLOBALS[0]=1;';
  assert.equal(Gm.ikFromScript(script), "f00dfeed12");
  assert.equal(Gm.ikFromScript('window.foo={"ik":"0123456789"}'), "0123456789");
  assert.equal(Gm.ikFromScript("var x = 1;"), null);
  assert.equal(Gm.sliceArray('[1,"]",[2]] tail', 0), '[1,"]",[2]]');
});

test("Gmail 'Show original' page → raw source (no DOM parsing)", () => {
  const raw = 'From: "PayPal" <a@b.test>\nSubject: Hi & <you>\n\nBody "quoted" é';
  const esc = raw.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace("é", "&#233;");
  const html = '<html><body><div class="x"><a href="?view=att&amp;th=18c&amp;attid=0&amp;disp=comp&amp;safe=1&amp;zw">Download Original</a></div>' +
    '<pre class="raw_message_text" id="raw_message_text">' + esc + "</pre></body></html>";
  const got = plain(Gm.rawFromOriginalHtml(html, U.decodeEntities));
  assert.equal(got.raw, raw);
  assert.equal(got.downloadHref, "?view=att&th=18c&attid=0&disp=comp&safe=1&zw");
  const none = plain(Gm.rawFromOriginalHtml("<html>login</html>", U.decodeEntities));
  assert.deepEqual(none, { raw: null, downloadHref: null });
  assert.equal(U.looksLikeRawEmail(got.raw), true);
  assert.equal(U.looksLikeRawEmail("<html><body>Sign in</body></html>"), false);
});

test("Gmail download_url attribute and spam view detection", () => {
  assert.deepEqual(plain(Gm.parseDownloadUrl("application/pdf:Invoice.pdf.exe:https://mail.google.com/mail/u/0/?ik=1")), { mime: "application/pdf", name: "Invoice.pdf.exe", url: "https://mail.google.com/mail/u/0/?ik=1" });
  assert.equal(Gm.parseDownloadUrl("garbage"), null);
  assert.equal(Gm.isSpamHash("#spam"), true);
  assert.equal(Gm.isSpamHash("#spam/FMfcgzQXJ"), true);
  assert.equal(Gm.isSpamHash("#search/in%3Aspam"), true);
  assert.equal(Gm.isSpamHash("#inbox"), false);
  assert.equal(Gm.isSpamHash("#spammy-label"), false);
});

// ------------------------------------------------------------------------------------- Outlook
test("Outlook ItemId, junk folder, sender titles, hosts", () => {
  assert.equal(Ol.itemIdFromUrl("https://outlook.live.com/mail/0/inbox/id/AQMkADAwATM0MDAAMS1iNTcwLWI2NTEtMDACLTAwCgBGAAAD%3D"), "AQMkADAwATM0MDAAMS1iNTcwLWI2NTEtMDACLTAwCgBGAAAD=");
  assert.equal(Ol.itemIdFromUrl("https://outlook.office.com/mail/deeplink/read?ItemID=AAMkAGI2TG93AAA%3D"), "AAMkAGI2TG93AAA=");
  assert.equal(Ol.itemIdFromUrl("https://outlook.live.com/mail/0/inbox"), null);
  assert.equal(Ol.itemIdFromUrl("https://outlook.live.com/mail/0/inbox/id/%3Cscript%3E"), null);
  assert.equal(Ol.isJunkPath("/mail/0/junkemail"), true);
  assert.equal(Ol.isJunkPath("/mail/junkemail/id/AAA"), true);
  assert.equal(Ol.isJunkPath("/mail/0/inbox"), false);
  assert.deepEqual(plain(Ol.addressFromTitle("pp@gmail.com", "PayPal Service")), { name: "PayPal Service", address: "pp@gmail.com" });
  assert.deepEqual(plain(Ol.addressFromTitle("PayPal <service@paypal.com>", "")), { name: "PayPal", address: "service@paypal.com" });
  assert.equal(Ol.addressFromTitle("Your account is limited", "x"), null);
  assert.equal(Ol.isOutlookHost("outlook.cloud.microsoft"), true);
  assert.equal(Ol.isOutlookHost("outlook.office365.com"), true);
  assert.equal(Ol.isOutlookHost("evil-outlook.live.com.test"), false);
  assert.equal(Ol.looksLikeFileName("invoice.pdf"), true);
  assert.equal(Ol.looksLikeFileName("someone@x.com"), false);
});

test("Outlook live DOM (2026-11): row subject leaf, FROM heading text", () => {
  // Row leaves in document order: avatar initials are skipped by the adapter; sender has title=address,
  // the date has a title in the UI language (words, not only digits), subject + preview have none.
  const leaves = [
    { text: "Microsoft", title: "msa@communication.microsoft.com", sender: true },
    { text: "Updates to our terms of use", title: "" },
    { text: "8/15/2026", title: "Sat 8/15/2026 4:34 AM" },
    { text: "Hello, you are receiving this", title: "" },
  ];
  assert.equal(Ol.rowSubjectIndex(leaves), 1);
  const ar = [{ text: "x", title: "x@y.com", sender: true }, { text: "١٥/٨/٢٠٢٦", title: "السبت ١٥/٨/٢٠٢٦" }, { text: "فاتورة", title: "" }];
  assert.equal(Ol.rowSubjectIndex(ar), 2);
  assert.equal(Ol.rowSubjectIndex([{ text: "Lunch?", title: "" }]), 0); // sender not found: first untitled leaf
  assert.equal(Ol.rowSubjectIndex([]), -1);
  // Reading pane FROM heading: external sender = "Name<address>" (no space), yourself/contacts = name only.
  assert.deepEqual(plain(Ol.addressFromTitle("", "Microsoft<msa@communication.microsoft.com>")), { name: "Microsoft", address: "msa@communication.microsoft.com" });
  assert.equal(Ol.addressFromTitle("", "kenan 1099"), null);
  assert.equal(Ol.SELECTORS.rows[0].includes("[role=main]"), false); // the list is NOT inside [role=main]
  assert.equal(Ol.SELECTORS.body.some((s) => s.includes("allowTextSelection")), false); // matched the subject
  // "View message source" dialog text (CRLF, folded From header) -> sender address used to match the open message.
  const src = "Received: from x by y\r\nFrom: =?utf-8?B?a2VuYW4=?=\r\n <Me@Outlook.com>\r\nSubject: hi\r\n\r\nFrom: body@evil.test\r\n";
  assert.equal(Ol.rawFromAddress(src), "me@outlook.com");
  assert.equal(Ol.rawFromAddress("From: plain@x.test\nSubject: a\n\nbody"), "plain@x.test");
  assert.equal(Ol.rawFromAddress("Subject: none\n\nFrom: body@x.test"), "");
  assert.ok(U.looksLikeRawEmail(src));
});

// ------------------------------------------------------------------------------------- language/theme
test("pickLang follows the page, then the browser", () => {
  assert.equal(U.pickLang("ar", ["en-US"]), "ar");
  assert.equal(U.pickLang("ar-AE", []), "ar");
  assert.equal(U.pickLang("en", ["ar-AE"]), "en"); // the page language wins
  assert.equal(U.pickLang("", ["ar-AE", "en"]), "ar");
  assert.equal(U.pickLang(null, "ar"), "ar");
  assert.equal(U.pickLang(undefined, ["fr-FR"]), "en");
  assert.equal(U.pickLang("", []), "en");
  assert.equal(Wip.pickLang("AR", []), "ar");
  assert.equal(U.t("score", "ar", 72), "الخطورة 72/100");
  assert.equal(U.t("progress", "en", 12, 50), "12 / 50");
});

test("isDarkColor / toneOf", () => {
  assert.equal(U.isDarkColor("rgb(32, 33, 36)"), true);
  assert.equal(U.isDarkColor("rgb(255, 255, 255)"), false);
  assert.equal(U.isDarkColor("rgba(0, 0, 0, 0)"), null);
  assert.equal(U.isDarkColor("transparent"), null);
  assert.equal(U.toneOf("HIGH-RISK SCAM", 66), "dangerous");
  assert.equal(U.toneOf("SUSPICIOUS", 40), "suspicious");
  assert.equal(U.toneOf("SAFE", 5), "safe");
  assert.equal(U.toneOf(null, 65), "dangerous");
  assert.equal(U.toneOf(null, 30), "suspicious");
  assert.equal(U.toneOf(null, null), "error");
});

// ------------------------------------------------------------------------------------- look-alikes
test("punycode decode round-trips with Node's encoder", () => {
  assert.equal(U.punyDecode("mnchen-3ya"), "münchen");
  for (const d of ["pаypal.com", "аррӏе.com", "bücher.de", "مثال.إختبار", "例え.テスト"]) {
    assert.equal(U.toUnicodeHost(domainToASCII(d)), d.toLowerCase(), d);
  }
  assert.equal(U.toUnicodeHost("xn--zz.com"), "xn--zz.com"); // invalid label kept
  assert.throws(() => U.punyDecode("é-x"));
});

test("localChecks flags look-alike tricks", () => {
  // Cyrillic "а" inside PayPal in the subject (fixture phish_paypal_cyrillic).
  let f = U.localChecks({ from_name: "PayPal Support", from_address: "paypal.support.team2026@gmail.com", subject: "Your PаyPal account has been limited" });
  assert.deepEqual(codes(f), ["DISPLAY_NAME_CONFUSABLE:scam", "FREEMAIL_BRAND_SENDER:suspicious"]);
  assert.match(f[0].evidence, /P\\u0430yPal/);
  assert.ok(f.every((x) => x.en && x.ar));

  // Punycode sender domain that decodes to a mixed-script "paypal".
  f = U.localChecks({ from_name: "Service", from_address: "service@" + domainToASCII("pаypal.com"), subject: "Hello" });
  assert.deepEqual(codes(f), ["IDN_MIXED_SCRIPT:scam"]);
  assert.match(f[0].en, /paypal/);

  // Whole-Cyrillic domain label that imitates "apple" → look-alike; pure Arabic IDN → only punycode.
  f = U.localChecks({ from_address: "id@" + domainToASCII("аррӏе.com") });
  assert.equal(f.some((x) => x.level === "scam"), true);
  f = U.localChecks({ from_address: "info@" + domainToASCII("مثال.com"), from_name: "شركة مثال" });
  assert.deepEqual(codes(f), ["PUNYCODE_DOMAIN:suspicious"]);

  // ASCII typosquats and brand-in-domain.
  assert.deepEqual(codes(U.localChecks({ from_address: "service@paypa1.com" })), ["SENDER_LOOKALIKE:scam"]);
  assert.deepEqual(codes(U.localChecks({ from_address: "security@rnicrosoft.com" })), ["SENDER_LOOKALIKE:scam"]);
  assert.deepEqual(codes(U.localChecks({ from_address: "alerts@paypal-support-center.test" })), ["SENDER_LOOKALIKE:suspicious"]);

  // Hidden characters / reversed text.
  assert.deepEqual(codes(U.localChecks({ subject: "Pay​Pal: verify now" })), ["INVISIBLE_IN_TOKEN:suspicious"]);
  assert.deepEqual(codes(U.localChecks({ subject: "invoice_‮fdp.exe" })), ["BIDI_OVERRIDE:scam"]);

  // Display name shows another address.
  f = U.localChecks({ from_name: "service@paypal.com", from_address: "x123@mailer.test" });
  assert.deepEqual(codes(f), ["DISPLAY_NAME_ADDRESS_SPOOF:suspicious"]);
});

test("localChecks stays quiet on ordinary mail (false-positive guard)", () => {
  const quiet = [
    { from_name: "PayPal", from_address: "service@paypal.com", subject: "Your receipt from Noon" },
    { from_name: "PayPal", from_address: "service@mail.paypal.com", subject: "You sent a payment" },
    { from_name: "بنك أبوظبي التجاري", from_address: "alerts@adcb.com", subject: "تم خصم مبلغ ٢٥٠ درهم من حسابك" },
    { from_name: "أحمد", from_address: "ahmed@gmail.com", subject: "تم الاستلام، شكراً" },
    { from_name: "Sara (Apple Store fan)", from_address: "sara@gmail.com", subject: "Lunch?" },
    { from_name: "Dubai Mall", from_address: "news@thedubaimall.com", subject: "Fabric sale this weekend" },
    { from_name: "Ivan Petrov", from_address: "ivan@example.ru", subject: "Привет, как дела?" },
    { from_name: "فاطمة", from_address: "f@example.ae", subject: "مرحبا‌بك" }, // ZWNJ in Arabic
    { from_name: "Family", from_address: "a@example.com", subject: "👨‍👩‍👧 photos" }, // emoji ZWJ
    { from_name: "Microsoft", from_address: "account-security-noreply@accountprotection.microsoft.com", subject: "Microsoft account security code" },
    { from_name: "Newsletter", from_address: "hello@example.com", subject: "Weekly digest ‌‌‌ " },
  ];
  for (const q of quiet) assert.deepEqual(plain(U.localChecks(q)), [], JSON.stringify(q));
});

test("localLevel ordering", () => {
  assert.equal(U.localLevel([], [], null), null);
  assert.equal(U.localLevel([{ level: "suspicious" }], [{ match: "lure" }], null), "suspicious");
  assert.equal(U.localLevel([], [{ match: "ioc" }], null), "scam");
  assert.equal(U.localLevel([], [{ match: "lure" }], null), "campaign");
  assert.equal(U.localLevel([], [], { available: true, p_scam: 0.95 }), "model");
  assert.equal(U.localLevel([], [], { available: true, p_scam: 0.5 }), null);
  assert.equal(U.localLevel([], [], { available: false, p_scam: null }), null);
});

// ------------------------------------------------------------------------------------- raw cap
test("capRaw keeps all headers and stays under the byte cap", () => {
  const head = "From: a@b.test\r\nSubject: big\r\nDKIM-Signature: v=1; d=b.test\r\n";
  const small = head + "\r\nhello";
  assert.deepEqual(plain(U.capRaw(small)), { raw: small, truncated: false });
  const big = head + "\r\n" + "é".repeat(1500000); // 3 MB of UTF-8
  const out = U.capRaw(big, 2 * 1024 * 1024);
  assert.equal(out.truncated, true);
  assert.ok(out.raw.startsWith(head));
  assert.ok(new TextEncoder().encode(out.raw).length <= 2 * 1024 * 1024);
  assert.match(out.raw, /SAQR: message truncated/);
});

// ------------------------------------------------------------------------------------- fixtures
test("shared .eml fixtures look like raw emails", () => {
  const dir = path.join(REPO, "tests", "fixtures", "emails");
  if (!fs.existsSync(dir)) return;
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".eml"))) {
    assert.equal(U.looksLikeRawEmail(fs.readFileSync(path.join(dir, f), "utf8")), true, f);
  }
});

test("normaliseResult reads the contract response and the background summary", () => {
  const file = path.join(REPO, "tests", "fixtures", "contract", "analyze_email_response.json");
  const full = JSON.parse(fs.readFileSync(file, "utf8"));
  let r = plain(U.normaliseResult({ ok: true, full }));
  assert.equal(r.tone, "dangerous");
  assert.equal(r.score, full.risk_score);
  assert.equal(r.flags[0].code, "DISPLAY_NAME_CONFUSABLE");
  assert.ok(r.flags.every((x) => x.points > 0));
  assert.ok(r.codes.includes("DMARC_PASS"));
  assert.equal(r.auth.spf, full.authentication.spf.result);
  assert.equal(r.hasHeaders, true);
  assert.equal(r.scanId, full.scan_id);
  assert.ok(r.campaigns.length >= 1 && r.campaigns[0].title_en);
  assert.ok(r.unicode.length >= 1 && r.unicode[0].sample_escaped);

  // Background summary only (summariseEmail in background.js): camelCase, flags without points.
  r = plain(U.normaliseResult({
    ok: true,
    verdict: { verdict: "SUSPICIOUS", score: 41, flags: [{ code: "PUNYCODE_DOMAIN", sev: "high", en: "e", ar: "ع" }], explanationEn: "x", explanationAr: "س",
      hasHeaders: false, auth: { spf: "not_checked", dkim: "none", dmarc: "not_checked" }, campaigns: [{ id: "c", titleEn: "T", titleAr: "ت", match: "lure", points: 20 }],
      unicode: [{ where: "from.domain", kind: "punycode", sample: "xn--x", skeleton: "x" }], scanId: "EML-1" },
  }));
  assert.equal(r.tone, "suspicious");
  assert.equal(r.flags.length, 1);
  assert.equal(r.hasHeaders, false);
  assert.equal(r.campaigns[0].title_ar, "ت");
  assert.equal(r.unicode[0].sample_escaped, "xn--x");
  assert.equal(r.scanId, "EML-1");

  r = plain(U.normaliseResult({ ok: true, verdict: {} }));
  assert.equal(r.tone, "error");
});

test("campaign + model inputs match the shared contracts", () => {
  const meta = {
    from_name: "PayPal Support",
    from_address: "x@Paypal-Support-Center.test",
    subject: "Your account has been limited",
    body_text: "Please confirm your identity to restore access",
    links: [{ href: "https://www.google.com/url?q=https://pp-resolution.test/x", text: "here" }],
  };
  const ci = plain(U.campaignInput(meta));
  assert.equal(ci.sender_domain, "paypal-support-center.test");
  assert.deepEqual(ci.link_domains, ["www.google.com"]); // collectLinks unwraps before this in the page
  const mi = plain(U.modelInput(meta, { auth: { spf: "pass" }, flags: ["X"] }));
  assert.deepEqual(Object.keys(mi).sort(), ["auth", "body_text", "flags", "from_address", "from_name", "link_domains", "reply_to", "subject"]);
  assert.deepEqual(mi.auth, { spf: "pass", dkim: "none", dmarc: "none" });

  if (!G.SaqrCampaigns) return; // lib/campaign_match.js (WS-F1) not present yet
  const feed = JSON.parse(fs.readFileSync(path.join(REPO, "tests", "fixtures", "contract", "campaigns_feed.json"), "utf8"));
  const hits = plain(G.SaqrCampaigns.matchFeed(feed, ci));
  assert.equal(hits[0].id, "cmp-7f3a9c21");
  assert.equal(hits[0].match, "ioc");
  const lure = plain(G.SaqrCampaigns.matchFeed(feed, U.campaignInput(Object.assign({}, meta, { from_address: "a@gmail.com", links: [] }))));
  assert.equal(lure[0].match, "lure");
});

test("sha256Hex gives a valid background message_key", async () => {
  const k = await U.sha256Hex("gmail:msg-f:1786137620214310647");
  assert.match(k, /^[0-9a-f]{64}$/);
  assert.match(k, /^[A-Za-z0-9:_.-]{8,128}$/); // background.js MESSAGE_KEY_RE
  assert.equal(k, await U.sha256Hex("gmail:msg-f:1786137620214310647"));
});

test("WIP pill provider table", () => {
  assert.equal(Wip.providerFor("mail.yahoo.com", "/d/folders/1"), "Yahoo Mail");
  assert.equal(Wip.providerFor("www.icloud.com", "/mail/"), "iCloud Mail");
  assert.equal(Wip.providerFor("www.icloud.com", "/photos/"), null);
  assert.equal(Wip.providerFor("mail.google.com", "/"), null);
  assert.equal(Wip.displayUrl(Wip.APP_URL), "saqr-intel.vercel.app/citizen");
});

test("every citizen string has English and Arabic", () => {
  for (const [k, pair] of Object.entries(U.STR)) {
    assert.equal(pair.length, 2, k);
    assert.ok(pair[0] && pair[1], k);
  }
});
