// Search & Maps shield: extraction + badge decisions against small HTML fixtures (tiny DOM, no jsdom).
// Run: node --test extension/tests/content/
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { parseHTML } = require("./minidom.cjs");

const EXT = path.resolve(__dirname, "..", "..");
const FIX = path.join(__dirname, "fixtures");

function load() {
  const ctx = vm.createContext({ console, URL, URLSearchParams, setTimeout, clearTimeout, atob: (s) => Buffer.from(s, "base64").toString("binary") });
  ctx.globalThis = ctx;
  for (const f of ["lib/search_core.js", "content/search.js"]) {
    vm.runInContext(fs.readFileSync(path.join(EXT, f), "utf8"), ctx, { filename: f });
  }
  return ctx;
}

const G = load();
const C = G.SaqrSearchCore;
const S = G.SaqrSearch;
const plain = (x) => JSON.parse(JSON.stringify(x));
const page = (name) => parseHTML(fs.readFileSync(path.join(FIX, name), "utf8"));
const urlsOf = (items, kind) => items.filter((i) => !kind || i.kind === kind).map((i) => i.url);

// ------------------------------------------------------------------------------------- core
test("siteOf / engineOfUrl: Google ccTLDs, Maps, Bing; nothing else", () => {
  const at = (u) => C.siteOf(new URL(u));
  assert.equal(at("https://www.google.com/search?q=tamm"), "google");
  assert.equal(at("https://www.google.ae/search?q=tamm"), "google");
  assert.equal(at("https://www.google.com.sa/search?q=x"), "google");
  assert.equal(at("https://www.google.co.uk/search?q=x"), "google");
  assert.equal(at("https://www.google.com/maps/place/x/@24.3,54.5,17z"), "maps");
  assert.equal(at("https://www.bing.com/search?q=x"), "bing");
  for (const u of ["https://www.google.com/", "https://mail.google.com/mail/u/0/", "https://www.google.evil.com/search", "https://www.bing.com/maps"]) {
    assert.equal(at(u), null, u);
  }
  assert.equal(C.engineOfUrl("https://www.google.ae/maps/place/x"), "google");
  assert.equal(C.engineOfUrl("http://www.google.com/search?q=x"), null); // https only
  assert.equal(C.engineOfUrl("https://evil.example/search"), null);
  assert.equal(C.engineOfUrl("not a url"), null);
});

test("resolveHref: ad click wrappers resolve to the advertiser, from the DOM only", () => {
  const none = () => null;
  assert.equal(C.resolveHref("https://www.google.com/aclk?sa=l&adurl=https://tamm-smart-pay.net/x%3Fa%3D1", none), "https://tamm-smart-pay.net/x?a=1");
  const attrs = { "data-pcu": "https://advertiser.example/landing,https://advertiser.example/" };
  assert.equal(C.resolveHref("/aclk?sa=l&ai=abc", (k) => attrs[k] || null), "https://advertiser.example/landing");
  assert.equal(C.resolveHref("https://www.googleadservices.com/pagead/aclk?sa=L", (k) => (k === "data-dtld" ? "fake-fab.example" : null)), "https://fake-fab.example/");
  assert.equal(C.resolveHref("https://www.google.ae/url?q=https://evil.example/login&sa=U", none), "https://evil.example/login");
  const u = "a1" + Buffer.from("https://evil.example/bing").toString("base64url");
  assert.equal(C.resolveHref("https://www.bing.com/ck/a?!&&p=1&u=" + u + "&ntb=1", none), "https://evil.example/bing");
  assert.equal(C.resolveHref("https://www.bing.com/aclk?ld=1&u=" + encodeURIComponent("https://ad.example/"), none), "https://ad.example/");
  assert.equal(C.resolveHref("https://www.google.com/search?q=x", none), null); // engine navigation
  assert.equal(C.resolveHref("https://www.google.com/url?q=javascript:alert(1)", none), null);
  assert.equal(C.resolveHref("javascript:alert(1)", none), null);
  assert.equal(C.resolveHref("https://www.tamm.abudhabi/", none), "https://www.tamm.abudhabi/");
  assert.equal(C.parseDisplayUrl("https://tamm-smart-pay.net › traffic-fines"), "https://tamm-smart-pay.net/");
  assert.equal(C.parseDisplayUrl("Sponsored"), null);
});

test("findPhones: UAE numbers; toll-free numbers in free text only after a phone word", () => {
  assert.deepEqual(plain(C.findPhones("Call 050 000 7781 or +971 2 444 4444")), ["050 000 7781", "+971 2 444 4444"]);
  assert.deepEqual(plain(C.findPhones("Hotline: 800 555")), ["800 555"]);
  assert.deepEqual(plain(C.findPhones("Call toll free 600 599 999")), ["600 599 999"]);
  assert.deepEqual(plain(C.findPhones("Only AED 600 500 this week, 800 2626 visitors")), []);
  assert.deepEqual(plain(C.findPhones("600 525500", true)), ["600 525500"]);
  assert.deepEqual(plain(C.findPhones("اتصل 800555")), ["800555"]);
  assert.equal(C.phoneFromTel("phone:tel:+971500007781"), "+971500007781");
  assert.equal(C.phoneFromTel("tel:800555"), "800555");
  assert.equal(C.phoneFromTel("https://x"), null);
});

// ------------------------------------------------------------------------------------- extraction
test("Google: sponsored ads (wrappers resolved), organic results, panel website, heuristic fallback", () => {
  const doc = page("google_serp.html");
  const items = S.collectLinks(doc, "google");
  assert.deepEqual(plain(urlsOf(items, "ad")), [
    "https://tamm-smart-pay.net/traffic-fines?gclid=1",
    "https://tamm-smart-pay.net/refund",
    "https://www.bankfab.com/en-ae/personal",
  ]);
  assert.deepEqual(plain(urlsOf(items, "organic")), [
    "https://es.adpolice.gov.ae/en/traffic",
    "https://uae-fines-refund.example/claim",
    "https://www.thenationalnews.com/uae/traffic-fines",
  ]);
  const panel = items.filter((i) => i.kind === "panel");
  assert.deepEqual(plain(panel.map((i) => [i.url, i.quiet])), [["https://www.tamm.abudhabi/", false]]);
  const fallback = items.filter((i) => i.kind === "result");
  assert.deepEqual(plain(fallback.map((i) => i.url)), ["https://es.adpolice.gov.ae/en/fines", "https://new-markup-scam.example/x"]);
  assert.ok(fallback.every((i) => i.quiet)); // fallback links never get a green tick
  const all = urlsOf(items).join(" ");
  assert.ok(!all.includes("google.com/search") && !all.includes("outside-results"));
  // ads: one block per ad, so one badge per ad
  const adBlocks = new Set(items.filter((i) => i.kind === "ad").map((i) => i.block));
  assert.equal(adBlocks.size, 2);
});

test("Google: phones in ads and the knowledge panel, with the claimed institution", () => {
  const phones = S.collectPhones(page("google_serp.html"), "google").map((p) => ({ phone: p.phone, context: p.context, claim: p.claim, tag: p.node.localName }));
  assert.equal(phones.length, 3);
  assert.equal(phones[0].phone, "050 000 7781");
  assert.equal(phones[0].context, "ad");
  assert.match(phones[0].claim, /Abu Dhabi Police Traffic Fine Payment/);
  assert.deepEqual([phones[1].phone, phones[1].context, phones[1].tag], ["600 525500", "ad", "span"]);
  assert.match(phones[1].claim, /First Abu Dhabi Bank/);
  assert.deepEqual([phones[2].phone, phones[2].context, phones[2].claim], ["02 444 4444", "panel", "TAMM Service Center"]);
});

test("Bing: ad wrappers (u=a1<base64>), organic results, ad phones", () => {
  const doc = page("bing_serp.html");
  const items = S.collectLinks(doc, "bing");
  assert.deepEqual(plain(urlsOf(items, "ad")), ["https://emiratespost-track-uae.com/parcel"]);
  assert.deepEqual(plain(urlsOf(items, "organic")), ["https://www.emiratespost.ae/track", "https://paypal-login-verify.com/x"]);
  const phones = S.collectPhones(doc, "bing");
  assert.deepEqual(plain(phones.map((p) => [p.phone, p.context])), [["055 123 4567", "ad"], ["600 599 999", "ad"]]);
  assert.match(phones[0].claim, /Emirates Post/);
});

test("Google Maps place panel: website button + phone button, claim = place name", () => {
  const doc = page("maps_place.html");
  assert.deepEqual(plain(urlsOf(S.collectLinks(doc, "maps"))), ["https://emiratespost-track-uae.com/"]);
  const phones = S.collectPhones(doc, "maps");
  assert.deepEqual(plain(phones.map((p) => [p.phone, p.context, p.claim])), [["+971500007781", "maps", "Emirates Post Customer Center - Abu Dhabi"]]);
});

// ------------------------------------------------------------------------------------- decisions
const TAMM = { id: "tamm", nameEn: "TAMM Abu Dhabi", nameAr: "منصة تم - حكومة أبوظبي", officialDomains: ["tamm.abudhabi"], officialPhones: ["800 555"] };
const SCAM = { verdict: "HIGH-RISK SCAM", score: 92, official: false, entity: TAMM, domain: "tamm-smart-pay.net",
  reasons: [{ code: "BRAND_IMPERSONATION", en: "Uses the name of TAMM", ar: "يستخدم اسم تم" }] };

test("decideLink: red + locked for scams, amber for suspicious, green only for official UAE sites", () => {
  const red = C.decideLink(SCAM, "en");
  assert.deepEqual([red.level, red.inert, red.label], ["danger", true, "SAQR: scam — imitates TAMM Abu Dhabi"]);
  assert.match(red.tip, /Uses the name of TAMM/);
  assert.match(red.tip, /Use only: tamm\.abudhabi/);
  assert.equal(C.decideLink(SCAM, "ar").label, "صقر: احتيال — ينتحل صفة منصة تم - حكومة أبوظبي");
  assert.equal(C.decideLink({ ...SCAM, entity: null }, "en").label, "SAQR: scam");
  const amber = C.decideLink({ verdict: "SUSPICIOUS", score: 45, entity: null, reasons: [] }, "en");
  assert.deepEqual([amber.level, amber.inert, amber.label], ["warn", false, "SAQR: suspicious"]);
  const tick = C.decideLink({ verdict: "SAFE", score: 0, official: true, entity: { nameEn: "Abu Dhabi Police", nameAr: "شرطة أبوظبي" }, reasons: [] }, "ar");
  assert.deepEqual([tick.level, tick.label], ["official", "رسمي: شرطة أبوظبي"]);
  assert.equal(C.decideLink({ verdict: "SAFE", score: 0, official: true, entity: null }, "en", { quiet: true }), null);
  assert.equal(C.decideLink({ verdict: "SAFE", score: 10, official: false, entity: null }, "en"), null); // no noise
  assert.equal(C.decideLink(null, "en"), null);
});

test("decidePhone: fake helpline red with the official number, unlisted amber, official green", () => {
  const ent = { nameEn: "Emirates Post", nameAr: "بريد الإمارات", officialPhones: ["600 599 999"] };
  const red = C.decidePhone({ level: "danger", entity: ent, reasons: [{ en: "Institutions don't use personal mobile numbers", ar: "x" }] }, "en");
  assert.deepEqual([red.level, red.label], ["danger", "Not the official number (official: 600 599 999)"]);
  assert.equal(C.decidePhone({ level: "danger", entity: ent, reasons: [] }, "ar").label, "ليس الرقم الرسمي (الرسمي: 600 599 999)");
  assert.equal(C.decidePhone({ level: "danger", entity: null, reasons: [] }, "en").label, "Scam number: linked to fake listings");
  assert.equal(C.decidePhone({ level: "caution", entity: ent, reasons: [] }, "en").label, "Not on the official list (official: 600 599 999)");
  assert.equal(C.decidePhone({ level: "official", entity: ent, reasons: [] }, "en").label, "Official Emirates Post number");
  assert.equal(C.decidePhone({ level: "none" }, "en"), null);
  assert.equal(C.decidePhone(null, "en"), null);
});

// ------------------------------------------------------------------------------------- page flow
function fakeBackend() {
  const calls = [];
  const verdictFor = (url) => {
    const host = new URL(url).hostname;
    if (host === "tamm-smart-pay.net" || host === "uae-fines-refund.example") return SCAM;
    if (host === "new-markup-scam.example") return { verdict: "SUSPICIOUS", score: 40, entity: null, reasons: [] };
    if (host.endsWith("adpolice.gov.ae")) return { verdict: "SAFE", score: 0, official: true, entity: { nameEn: "Abu Dhabi Police", nameAr: "شرطة أبوظبي" }, reasons: [] };
    if (host === "www.tamm.abudhabi") return { verdict: "SAFE", score: 0, official: true, entity: TAMM, reasons: [] };
    return { verdict: "SAFE", score: 0, official: false, entity: null, reasons: [] };
  };
  const send = async (msg) => {
    calls.push(plain(msg));
    if (msg.type === "searchVerdicts") return { ok: true, results: Object.fromEntries(msg.urls.map((u) => [u, verdictFor(u)])) };
    if (msg.type === "checkPhones") {
      return { ok: true, results: msg.items.map((it) => (it.phone === "050 000 7781" ? { level: "danger", entity: TAMM, reasons: [] } : { level: "none" })) };
    }
    return { ok: false };
  };
  return { calls, send };
}

const badges = (doc) => doc.querySelectorAll(".saqr-sb-badge").map((b) => [b.getAttribute("data-saqr-level"), b.textContent]);

test("pass: badges before the click, scam links locked, one badge per result, cached on the next pass", async () => {
  const doc = page("google_serp.html");
  const be = fakeBackend();
  const shield = S.createShield({ doc, site: "google", send: be.send, lang: "en", navigate: () => {} });
  await shield.pass();
  assert.deepEqual(plain(badges(doc)), [
    ["danger", "⛔ SAQR: scam — imitates TAMM Abu Dhabi"], // the TAMM ad
    ["danger", "⛔ Not the official number (official: 800 555)"], // its phone
    ["official", "✓ Official: Abu Dhabi Police"], // adpolice result (its "Fines" sitelink adds no second tick)
    ["danger", "⛔ SAQR: scam — imitates TAMM Abu Dhabi"],
    ["warn", "⚠ SAQR: suspicious"], // the changed-markup result, found by the fallback
    ["official", "✓ Official: TAMM Abu Dhabi"], // knowledge panel website button
  ]);
  const ad = doc.querySelector("[data-text-ad]");
  const locked = ad.querySelectorAll("a[data-saqr-inert]");
  assert.equal(locked.length, 2); // main ad link and its sitelink
  assert.equal(ad.querySelector(".saqr-sb-badge").getAttribute("title").split("\n")[0], "SAQR-INTEL checked this before you click:");
  assert.equal(doc.querySelectorAll("a[data-saqr-inert]").length, 3);
  assert.ok(!doc.querySelector("a[href*='thenationalnews']").hasAttribute("data-saqr-inert"));

  const sent = be.calls.length;
  await shield.pass();
  assert.equal(be.calls.length, sent); // every URL and phone already known
  assert.equal(badges(doc).length, 6);
  const [verdictCall] = be.calls.filter((c) => c.type === "searchVerdicts");
  assert.ok(verdictCall.urls.includes("https://www.bankfab.com/en-ae/personal"));
  assert.ok(!verdictCall.urls.some((u) => u.includes("google.com")));
});

test("locked link: the click is stopped and SAQR asks first; 'Open anyway' goes to the real address", async () => {
  const doc = page("google_serp.html");
  const be = fakeBackend();
  const went = [];
  const shield = S.createShield({ doc, site: "google", send: be.send, lang: "ar", navigate: (u) => went.push(u) });
  shield.install();
  await shield.pass();
  assert.equal(doc.listeners.click[0].capture, true);
  const heading = doc.querySelector("[data-text-ad] [role='heading']");
  let stopped = 0;
  const ev = (target, extra = {}) => ({ type: "click", target, preventDefault: () => stopped++, stopImmediatePropagation: () => {}, ...extra });
  shield.onActivate(ev(heading));
  assert.equal(stopped, 1);
  const guard = doc.querySelector("saqr-search-guard");
  assert.ok(guard);
  assert.match(guard.textContent, /انتظر! هذا الرابط يبدو احتيالياً/);
  assert.match(guard.textContent, /tamm\.abudhabi/);
  guard.querySelector("button.go").click();
  assert.deepEqual(went, ["https://tamm-smart-pay.net/traffic-fines?gclid=1"]);
  assert.equal(doc.querySelector("saqr-search-guard"), null);
  shield.onActivate(ev(heading)); // unlocked now
  assert.equal(stopped, 1);
  shield.onActivate(ev(doc.querySelector("a[href*='thenationalnews'] h3")));
  shield.onActivate(ev(doc.querySelector("#rso a[href*='uae-fines-refund'] h3"), { type: "keydown", key: "Tab" }));
  assert.equal(stopped, 1);
});

test("backend unreachable: no badges, nothing thrown, retried later", async () => {
  const doc = page("maps_place.html");
  let calls = 0;
  const shield = S.createShield({ doc, site: "maps", send: async () => (calls++, { ok: false, error: "offline" }), lang: "en", navigate: () => {} });
  await shield.pass();
  assert.equal(badges(doc).length, 0);
  await shield.pass();
  assert.ok(calls > 2, "failed lookups are asked again on the next pass");
});
