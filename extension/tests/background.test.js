// background.js message protocol (email contract section 5) with a minimal chrome stub.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { loadBackground, SENDERS, fixture } = require("./helpers.js");

const RESPONSE = fixture("contract/analyze_email_response.json");
const FEED = fixture("contract/campaigns_feed.json");
const KEY = "1e5db8c953536da65779f904afc014b420cf82d7580d0116432b50f271119fec";

function backendStub(handlers = {}) {
  return async (url, init) => {
    const path = new URL(url).pathname;
    if (handlers[path]) return handlers[path](url, init);
    if (path === "/api/analyze-email") return { status: 200, body: RESPONSE };
    return { status: 404, body: { detail: "Not Found" } };
  };
}

// Objects created inside the VM have another realm's prototypes: compare them as plain JSON.
const plain = (o) => JSON.parse(JSON.stringify(o));
const send = (bg, msg, sender) => bg.ctx.handleMessage(msg, sender).then(plain);
const meta = () => ({
  from_name: "PayPal Support",
  from_address: "paypal.support.team2026@gmail.com",
  subject: "Your account has been limited",
  body_text: "Please confirm your identity",
  links: [{ href: "https://paypal-account-review.test/x", text: "https://www.paypal.com" }],
  attachments: [{ name: "case.pdf", size: 15 }],
});

test("privileged messages are refused from web pages / content scripts", async () => {
  const bg = loadBackground(backendStub());
  for (const type of ["setApi", "allowHost", "tabVerdict", "scanTab", "modelExport", "modelImport", "modelReset", "modelStats", "saveEmailSettings"]) {
    const r = await send(bg, { type, url: "http://evil", host: "evil", model: {}, llm: null }, SENDERS.gmail);
    assert.equal(r.ok, false, type);
    assert.match(r.error, /Not allowed/);
  }
  // nothing was changed
  assert.equal(bg.chrome.storage.local.data.apiBaseUrl, undefined);
});

test("content-script messages only from the webmail hosts and only from this extension", async () => {
  const bg = loadBackground(backendStub());
  assert.equal((await send(bg, { type: "emailSettings" }, SENDERS.evil)).ok, false);
  assert.equal((await send(bg, { type: "emailSettings" }, SENDERS.otherExtension)).ok, false);
  assert.equal((await send(bg, { type: "emailSettings" }, SENDERS.gmail)).ok, true);
  assert.equal((await send(bg, { type: "emailSettings" }, SENDERS.options)).ok, true);
  assert.equal((await send(bg, null, SENDERS.gmail)).ok, false);
  assert.equal((await send(bg, { type: "nope" }, SENDERS.options)).ok, false);
});

test("emailScan validates the payload", async () => {
  const bg = loadBackground(backendStub());
  const bad = [
    { type: "emailScan", message_key: "x", meta: meta() },
    { type: "emailScan", message_key: "has spaces in it", meta: meta() },
    { type: "emailScan", message_key: KEY, meta: "string" },
    { type: "emailScan", message_key: KEY, meta: { ...meta(), links: "nope" } },
    { type: "emailScan", message_key: KEY, meta: { ...meta(), subject: 42 } },
    { type: "emailScan", message_key: KEY, meta: meta(), raw: { not: "text" } },
    { type: "emailScan", message_key: KEY, meta: {} },
  ];
  for (const m of bad) {
    const r = await send(bg, m, SENDERS.gmail);
    assert.equal(r.ok, false, JSON.stringify(m).slice(0, 80));
  }
  assert.equal(bg.calls.fetch.length, 0);
});

test("buildEmailRequest: limits, raw vs .eml, channel, provider from the sender", () => {
  const bg = loadBackground(backendStub());
  const long = "x".repeat(250_000);
  const links = Array.from({ length: 150 }, (_, i) => ({ href: "https://l" + i + ".test/", text: "" }));
  const { body, key, provider } = bg.ctx.buildEmailRequest(
    { type: "emailScan", provider: "outlook", message_key: KEY, meta: { ...meta(), body_text: long, links }, raw: "From: a@b.c\r\n\r\nhi" },
    SENDERS.gmail,
    false,
    { reporter: "r-0123456789abcdef0123456789abcdef", llm: null },
  );
  assert.equal(provider, "gmail"); // decided by the sender's host, not by the message
  assert.equal(key, "eml:gmail:" + KEY);
  assert.equal(body.source, "raw");
  assert.equal(body.text, "From: a@b.c\r\n\r\nhi");
  assert.equal(body.meta.body_text.length, 200_000);
  assert.equal(body.meta.links.length, 100);
  assert.equal(body.meta.provider, "gmail");
  assert.equal(body.meta.message_key, KEY);
  assert.equal(body.channel, "email");
  assert.equal(body.interception_channel, "PC_BROWSER_EXTENSION");
  assert.equal(body.reporter_id, "r-0123456789abcdef0123456789abcdef");
  assert.equal(body.llm, undefined);

  const big = bg.ctx.buildEmailRequest(
    { type: "emailScan", message_key: KEY, meta: meta(), raw: "Subject: é\r\n\r\n" + "y".repeat(300_000) },
    SENDERS.outlook,
    false,
    { reporter: null, llm: { base_url: "https://llm.example.com/v1", api_key: "k", model: "m" } },
  );
  assert.equal(big.body.source, "eml");
  assert.equal(big.body.text, null);
  assert.equal(Buffer.from(big.body.file_base64, "base64").toString("utf8").slice(0, 12), "Subject: é\r\n");
  assert.equal(big.provider, "outlook");
  assert.deepEqual(big.body.llm, { base_url: "https://llm.example.com/v1", api_key: "k", model: "m" });

  // A cut original (content script capRaw) is not byte-exact: it goes as pasted source, never as a file.
  const cut = bg.ctx.buildEmailRequest(
    { type: "emailScan", message_key: KEY, meta: meta(), raw: "Subject: x\r\n\r\n" + "y".repeat(300_000), truncated: true },
    SENDERS.gmail,
    false,
    { reporter: null, llm: null },
  );
  assert.equal(cut.body.source, "raw");
  assert.equal(cut.body.file_base64, null);
  assert.equal(cut.body.text.length, 200_000);
  assert.ok(cut.body.text.startsWith("Subject: x\r\n"));
});

test("emailScan: summarised verdict, cache, in-flight dedupe, no auto-training", { skip: !RESPONSE && "contract fixture missing" }, async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const bg = loadBackground(
    backendStub({
      "/api/analyze-email": async (url, init) => {
        await gate;
        return { status: 200, body: RESPONSE };
      },
    }),
  );
  const msg = { type: "emailScan", provider: "gmail", message_key: KEY, meta: meta() };
  const a = send(bg, msg, SENDERS.gmail);
  const b = send(bg, msg, SENDERS.gmail);
  await new Promise((r) => setTimeout(r, 20));
  release();
  const [ra, rb] = await Promise.all([a, b]);
  assert.equal(bg.calls.fetch.filter((c) => c.url.endsWith("/api/analyze-email")).length, 1);
  assert.equal(ra.ok, true);
  assert.deepEqual(ra, rb);
  const v = ra.verdict;
  assert.equal(v.kind, "email");
  assert.equal(v.domain, null);
  assert.equal(v.score, 100);
  assert.equal(v.verdict, "HIGH-RISK SCAM");
  assert.equal(v.entityEn, "PayPal");
  assert.equal(v.from.address, "paypal.support.team2026@gmail.com");
  assert.equal(v.auth.dmarc, "pass");
  assert.equal(v.auth.dkim, "pass");
  assert.equal(v.unicode[0].kind, "mixed_script");
  assert.equal(v.campaigns[0].id, "cmp-7f3a9c21");
  assert.equal(v.links[0].mismatch, true);
  assert.ok(v.flags.length > 0 && v.flags.length <= 6);
  assert.ok(v.notes.some((n) => n.code === "DMARC_PASS"));
  assert.deepEqual(ra.full.model_features, RESPONSE.model_features);
  assert.equal(ra.full.timings, undefined);

  const body = JSON.parse(bg.calls.fetch[0].init.body);
  assert.equal(body.interception_channel, "PC_BROWSER_EXTENSION");
  assert.match(body.reporter_id, /^r-[0-9a-f]{32}$/);
  assert.equal(body.use_user_model, true);

  const again = await send(bg, msg, SENDERS.gmail);
  assert.equal(again.cached, true);
  assert.equal(bg.calls.fetch.length, 1);
  const lookup = await send(bg, { type: "emailVerdict", message_key: KEY }, SENDERS.gmail);
  assert.equal(lookup.verdict.score, 100);
  // A HIGH-RISK verdict does not train the personal model by itself.
  assert.equal(bg.chrome.storage.local.data.userModel, undefined);

  const open = await send(bg, { type: "openEmailVerdict", message_key: KEY }, SENDERS.gmail);
  assert.equal(open.ok, true);
  assert.match(bg.calls.tabsCreate[0].url, /^chrome-extension:\/\/[^/]+\/blocked\.html\?mode=check&d=/);
  assert.equal(bg.calls.tabsCreate[0].openerTabId, 7);
});

test("emailScan reports backend errors without throwing", async () => {
  const bg = loadBackground(backendStub({ "/api/analyze-email": async () => ({ status: 500, body: { detail: "boom" } }) }));
  const r = await send(bg, { type: "emailScan", message_key: KEY, meta: meta() }, SENDERS.gmail);
  assert.deepEqual([r.ok, r.error, r.status], [false, "boom", 500]);
});

test("a 422 for the original source retries once with the visible email only", async () => {
  const bodies = [];
  const bg = loadBackground(
    backendStub({
      "/api/analyze-email": async (url, init) => {
        bodies.push(JSON.parse(init.body));
        return bodies.length === 1 ? { status: 422, body: { detail: [{ msg: "bad raw" }] } } : { status: 200, body: RESPONSE };
      },
    }),
  );
  const r = await send(bg, { type: "emailScan", message_key: KEY, meta: meta(), raw: "garbage" }, SENDERS.gmail);
  assert.equal(r.ok, true);
  assert.equal(bodies[0].source, "raw");
  assert.equal(bodies[1].source, "text");
  assert.equal(bodies[1].text, null);
});

test("labels train the local model (from cached server features) and are deduplicated", { skip: !RESPONSE && "contract fixture missing" }, async () => {
  const bg = loadBackground(backendStub({ "/api/email-model/label": async () => ({ status: 200, body: { ok: true } }) }));
  await send(bg, { type: "emailScan", message_key: KEY, meta: meta() }, SENDERS.gmail);
  const r1 = await send(bg, { type: "modelLabel", message_key: KEY, label: "scam", source: "user" }, SENDERS.gmail);
  assert.deepEqual([r1.ok, r1.labels], [true, 1]);
  const r2 = await send(bg, { type: "modelLabel", message_key: KEY, label: "scam", source: "user" }, SENDERS.gmail);
  assert.equal(r2.duplicate, true);
  const model = bg.chrome.storage.local.data.userModel;
  assert.equal(model.classes.scam.docs, 1);
  assert.equal(model.classes.scam.counts[String(RESPONSE.model_features[0])], 1);
  await new Promise((r) => setTimeout(r, 20));
  const labelCall = bg.calls.fetch.find((c) => c.url.endsWith("/api/email-model/label"));
  assert.ok(labelCall, "server copy is taught too");
  assert.equal(JSON.parse(labelCall.init.body).scan_id, RESPONSE.scan_id);

  // changing the label moves the email from "scam" to "ham"
  const flip = await send(bg, { type: "modelLabel", message_key: KEY, label: "ham", source: "user" }, SENDERS.gmail);
  assert.equal(flip.labels, 1);
  const flipped = bg.chrome.storage.local.data.userModel;
  assert.deepEqual([flipped.classes.scam.docs, flipped.classes.ham.docs], [0, 1]);
  assert.equal(flipped.classes.scam.counts[String(RESPONSE.model_features[0])], undefined);

  // bad labels / sources
  assert.equal((await send(bg, { type: "modelLabel", input: {}, label: "maybe" }, SENDERS.gmail)).ok, false);
  assert.equal((await send(bg, { type: "modelLabel", input: {}, label: "ham", source: "auto" }, SENDERS.gmail)).ok, false);
  assert.equal((await send(bg, { type: "modelLabel", label: "ham" }, SENDERS.gmail)).ok, false);
  assert.equal((await send(bg, { type: "modelLabel", features: [70000], label: "ham" }, SENDERS.gmail)).ok, false);
});

test("Spam-folder learning is opt-in", async () => {
  const bg = loadBackground(backendStub());
  const msg = { type: "modelLabel", input: { from_address: "x@spam.test", subject: "win" }, label: "scam", source: "spam_folder" };
  const off = await send(bg, msg, SENDERS.outlook);
  assert.equal(off.ok, false);
  assert.equal((await send(bg, { type: "saveEmailSettings", learnSpam: true }, SENDERS.options)).learnSpam, true);
  const on = await send(bg, msg, SENDERS.outlook);
  assert.deepEqual([on.ok, on.labels], [true, 1]);
  assert.equal((await send(bg, { ...msg, label: "ham" }, SENDERS.outlook)).ok, false);
});

test("predict / export / import / reset", async () => {
  const bg = loadBackground(backendStub());
  const M = bg.ctx.SaqrModel;
  const model = M.newModel();
  for (let i = 0; i < 10; i++) {
    M.train(model, M.features({ subject: "win a prize now" }), "scam", "spam@x.test");
    M.train(model, M.features({ subject: "team meeting notes" }), "ham", "boss@work.test");
  }
  const imp = await send(bg, { type: "modelImport", model: JSON.stringify(model) }, SENDERS.options);
  assert.equal(imp.ok, true);
  assert.equal(imp.labels, 20);
  assert.equal(imp.server, "failed"); // stub has no such route: reported, not thrown
  const p = await send(bg, { type: "modelPredict", input: { subject: "win a prize now", from_address: "spam@x.test" } }, SENDERS.gmail);
  assert.equal(p.available, true);
  assert.ok(p.p_scam > 0.9);
  assert.equal(p.flag, "USER_MODEL_SCAM");
  const merged = await send(bg, { type: "modelImport", model }, SENDERS.options);
  assert.equal(merged.labels, 40);
  const exp = await send(bg, { type: "modelExport" }, SENDERS.options);
  assert.equal(exp.model.format, "saqr-user-model");
  assert.equal(exp.model.classes.ham.docs, 20);
  assert.equal((await send(bg, { type: "modelImport", model: "{not json" }, SENDERS.options)).ok, false);
  assert.equal((await send(bg, { type: "modelImport", model: { format: "x" } }, SENDERS.options)).ok, false);
  const reset = await send(bg, { type: "modelReset" }, SENDERS.options);
  assert.equal(reset.ok, true);
  assert.equal(bg.chrome.storage.local.data.userModel, undefined);
  const stats = await send(bg, { type: "modelStats" }, SENDERS.options);
  assert.deepEqual([stats.scam, stats.ham], [0, 0]);
});

test("own-AI settings: https only, key never returned, key kept when left empty", async () => {
  const bg = loadBackground(backendStub());
  const http = await send(bg, { type: "saveEmailSettings", llm: { base_url: "http://llm.example.com/v1", model: "m", api_key: "k" } }, SENDERS.options);
  assert.equal(http.ok, false);
  const ok = await send(bg, { type: "saveEmailSettings", llm: { base_url: "https://llm.example.com/v1/", model: "gpt-4o-mini", api_key: "sk-secret" } }, SENDERS.options);
  assert.equal(ok.ok, true);
  assert.deepEqual(plain(ok.llm), { base_url: "https://llm.example.com/v1", model: "gpt-4o-mini", hasKey: true });
  assert.ok(!JSON.stringify(ok).includes("sk-secret"));
  const pub = await send(bg, { type: "emailSettings" }, SENDERS.gmail);
  assert.ok(!JSON.stringify(pub).includes("sk-secret"));
  assert.equal(pub.autoScan, true);
  await send(bg, { type: "saveEmailSettings", llm: { base_url: "https://llm.example.com/v1", model: "other", api_key: "" } }, SENDERS.options);
  assert.equal(bg.chrome.storage.local.data.userLlm.api_key, "sk-secret");
  assert.deepEqual(plain(await bg.ctx.userLlmConfig()), { base_url: "https://llm.example.com/v1", api_key: "sk-secret", model: "other" });
  await send(bg, { type: "saveEmailSettings", llm: null }, SENDERS.options);
  assert.equal(await bg.ctx.userLlmConfig(), null);
  assert.equal((await send(bg, { type: "saveEmailSettings", autoScan: "yes" }, SENDERS.options)).ok, false);
});

test("campaign feed is cached and refreshed with If-None-Match", { skip: !FEED && "contract feed missing" }, async () => {
  const seen = [];
  const bg = loadBackground(
    backendStub({
      "/api/campaigns": async (url, init) => {
        seen.push(init.headers || {});
        return seen.length === 1 ? { status: 200, body: FEED, headers: { ETag: '"v1"' } } : { status: 304, body: {} };
      },
    }),
  );
  const a = await send(bg, { type: "campaigns" }, SENDERS.gmail);
  assert.equal(a.ok, true);
  assert.equal(a.feed.campaigns.length, 2);
  const b = await send(bg, { type: "campaigns" }, SENDERS.gmail);
  assert.equal(seen.length, 1, "served from the 6 h cache");
  const c = await send(bg, { type: "campaigns", force: true }, SENDERS.options);
  assert.equal(seen.length, 2);
  assert.equal(seen[1]["If-None-Match"], '"v1"');
  assert.equal(c.feed.campaigns.length, 2);
  assert.deepEqual(b.feed, a.feed);
});

test("openReport opens the result page in check mode; gmailIk only for Gmail", async () => {
  const bg = loadBackground(backendStub());
  const r = await send(bg, { type: "openReport", mode: "block", verdict: { verdict: "SUSPICIOUS", score: 40, url: "https://evil.test/" } }, SENDERS.outlook);
  assert.equal(r.ok, true);
  const u = new URL(bg.calls.tabsCreate[0].url);
  assert.equal(u.searchParams.get("mode"), "check");
  const d = JSON.parse(u.searchParams.get("d"));
  assert.deepEqual([d.kind, d.url, d.score], ["email", null, 40]);
  assert.equal((await send(bg, { type: "openReport", verdict: { x: "y".repeat(40_000) } }, SENDERS.outlook)).ok, false);
  assert.equal((await send(bg, { type: "gmailIk" }, SENDERS.outlook)).ok, false);
  bg.chrome.scripting = { executeScript: async () => [{ result: "a1b2c3d4e5" }] };
  assert.deepEqual(await send(bg, { type: "gmailIk" }, SENDERS.gmail), { ok: true, ik: "a1b2c3d4e5" });
  bg.chrome.scripting = { executeScript: async () => [{ result: "<script>" }] };
  assert.equal((await send(bg, { type: "gmailIk" }, SENDERS.gmail)).ok, false);
});

test("webmail apps themselves are not URL-scanned", async () => {
  const bg = loadBackground(backendStub());
  for (const u of ["https://mail.google.com/mail/u/0/", "https://outlook.office.com/mail/", "https://outlook.cloud.microsoft/mail/", "https://mail.proton.me/u/0/inbox"]) {
    assert.equal(await bg.ctx.shouldScan(u), false, u);
  }
  assert.equal(await bg.ctx.shouldScan("https://paypal-account-review.test/"), true);
});
