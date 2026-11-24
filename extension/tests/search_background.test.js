// background.js: Search & Maps shield messages (searchSettings / searchVerdicts / checkPhones).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { loadBackground, SENDERS, EXT_ORIGIN } = require("./helpers.js");

const ID = "saqrtestextensionid";
const GOOGLE = { id: ID, url: "https://www.google.ae/search?q=tamm+fine", tab: { id: 3, index: 0 } };
const MAPS = { id: ID, url: "https://www.google.com/maps/place/Emirates+Post/@24.3,54.5,17z", tab: { id: 4, index: 0 } };
const BING = { id: ID, url: "https://www.bing.com/search?q=emirates+post", tab: { id: 5, index: 0 } };
const plain = (o) => JSON.parse(JSON.stringify(o));
const send = (bg, msg, sender) => bg.ctx.handleMessage(msg, sender).then(plain);

const TAMM = { id: "tamm", name_en: "TAMM Abu Dhabi", name_ar: "منصة تم", official_domains: ["tamm.abudhabi"], official_phones: ["800555"], official_phones_display: ["800 555"] };

function backend() {
  return async (url, init) => {
    const path = new URL(url).pathname;
    const body = init.body ? JSON.parse(init.body) : null;
    if (path === "/api/batch-verdict") {
      return { status: 200, body: { results: body.urls.map((u) => (u.includes("tamm-smart-pay")
        ? { url: u, domain: "tamm-smart-pay.net", score: 92, verdict: "HIGH-RISK SCAM", official: false, entity: TAMM,
            reasons: [{ code: "BRAND_IMPERSONATION", en: "Uses the name of TAMM", ar: "يستخدم اسم تم" }] }
        : { url: u, domain: new URL(u).hostname, score: 0, verdict: "SAFE", official: false, entity: null, reasons: [] })) } };
    }
    if (path === "/api/check-phone") {
      return { status: 200, body: { status: "mobile_for_institution", level: "danger", entity: TAMM, reasons: [{ code: "MOBILE_FOR_INSTITUTION", en: "x", ar: "y" }] } };
    }
    return { status: 404, body: { detail: "Not Found" } };
  };
}

test("search messages only from Google / Bing pages of this extension; never privileged ones", async () => {
  const bg = loadBackground(backend());
  for (const s of [GOOGLE, MAPS, BING, SENDERS.options]) assert.equal((await send(bg, { type: "searchSettings" }, s)).ok, true);
  for (const s of [SENDERS.evil, SENDERS.gmail, SENDERS.otherExtension, { ...GOOGLE, url: "http://www.google.com/search?q=x" }]) {
    assert.equal((await send(bg, { type: "searchSettings" }, s)).ok, false);
  }
  // a search page may not use the Email Shield or settings messages
  for (const type of ["emailScan", "modelExport", "saveSearchSettings", "setApi"]) {
    assert.equal((await send(bg, { type, enabled: false }, GOOGLE)).ok, false, type);
  }
  assert.equal((await send(bg, { type: "saveSearchSettings", enabled: "no" }, SENDERS.options)).ok, false);
});

test("searchVerdicts: one batch call, compact verdicts, cached per URL", async () => {
  const bg = loadBackground(backend());
  const urls = ["https://tamm-smart-pay.net/fines", "https://www.thenationalnews.com/", "javascript:alert(1)", "https://tamm-smart-pay.net/fines"];
  const r = await send(bg, { type: "searchVerdicts", urls }, GOOGLE);
  assert.equal(r.ok, true);
  assert.deepEqual(Object.keys(r.results), ["https://tamm-smart-pay.net/fines", "https://www.thenationalnews.com/"]);
  const v = r.results["https://tamm-smart-pay.net/fines"];
  assert.equal(v.verdict, "HIGH-RISK SCAM");
  assert.deepEqual(v.entity, { id: "tamm", nameEn: "TAMM Abu Dhabi", nameAr: "منصة تم", officialDomains: ["tamm.abudhabi"], officialPhones: ["800 555"] });
  assert.equal(v.reasons[0].en, "Uses the name of TAMM");
  const calls = bg.calls.fetch.filter((c) => c.url.endsWith("/api/batch-verdict"));
  assert.equal(calls.length, 1);
  assert.deepEqual(JSON.parse(calls[0].init.body), { urls: ["https://tamm-smart-pay.net/fines", "https://www.thenationalnews.com/"] });
  await send(bg, { type: "searchVerdicts", urls: urls.slice(0, 2) }, BING);
  assert.equal(bg.calls.fetch.filter((c) => c.url.endsWith("/api/batch-verdict")).length, 1); // cache
});

test("searchVerdicts: more than 50 new URLs are split into batches; bad input refused", async () => {
  const bg = loadBackground(backend());
  const urls = Array.from({ length: 120 }, (_, i) => "https://site" + i + ".example/");
  const r = await send(bg, { type: "searchVerdicts", urls }, GOOGLE);
  assert.equal(Object.keys(r.results).length, 120);
  const sizes = bg.calls.fetch.filter((c) => c.url.endsWith("/api/batch-verdict")).map((c) => JSON.parse(c.init.body).urls.length);
  assert.deepEqual(sizes, [50, 50, 20]);
  assert.equal((await send(bg, { type: "searchVerdicts", urls: "https://x" }, GOOGLE)).ok, false);
  assert.equal((await send(bg, { type: "searchVerdicts", urls: [42] }, GOOGLE)).ok, false);
});

test("checkPhones: validated, sent with the claimed institution, cached", async () => {
  const bg = loadBackground(backend());
  const items = [{ phone: "050 000 7781", claimed_entity: "TAMM Service Center", context: "ad" }, { phone: "12", context: "evil" }];
  const r = await send(bg, { type: "checkPhones", items }, MAPS);
  assert.equal(r.ok, true);
  assert.equal(r.results[0].level, "danger");
  assert.deepEqual(r.results[0].entity.officialPhones, ["800 555"]);
  assert.equal(r.results[1], null); // too short: never sent
  const calls = bg.calls.fetch.filter((c) => c.url.endsWith("/api/check-phone"));
  assert.deepEqual(JSON.parse(calls[0].init.body), { phone: "050 000 7781", claimed_entity: "TAMM Service Center", context: "ad" });
  assert.equal(calls.length, 1);
  await send(bg, { type: "checkPhones", items: items.slice(0, 1) }, GOOGLE);
  assert.equal(bg.calls.fetch.filter((c) => c.url.endsWith("/api/check-phone")).length, 1);
});

test("Options toggle: 'Search & Maps shield' is on by default; off means no backend calls", async () => {
  const bg = loadBackground(backend());
  assert.equal((await send(bg, { type: "searchSettings" }, GOOGLE)).enabled, true);
  const off = await send(bg, { type: "saveSearchSettings", enabled: false }, { id: ID, url: EXT_ORIGIN + "options.html" });
  assert.deepEqual(off, { ok: true, enabled: false });
  assert.equal((await send(bg, { type: "searchSettings" }, GOOGLE)).enabled, false);
  const r = await send(bg, { type: "searchVerdicts", urls: ["https://tamm-smart-pay.net/"] }, GOOGLE);
  assert.deepEqual(r, { ok: true, off: true, results: {} });
  assert.equal(bg.calls.fetch.length, 0);
});

test("backend down: the content script gets ok:false (and asks again later)", async () => {
  const bg = loadBackground(async () => ({ status: 503, body: { detail: "waking up" } }));
  const r = await send(bg, { type: "searchVerdicts", urls: ["https://a.example/"] }, GOOGLE);
  assert.equal(r.ok, false);
  const p = await send(bg, { type: "checkPhones", items: [{ phone: "800555", claimed_entity: "TAMM" }] }, GOOGLE);
  assert.equal(p.ok, false);
});
