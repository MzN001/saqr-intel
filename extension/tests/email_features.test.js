// Parity of lib/email_features.js + lib/user_model.js with saqr/intel/user_model.py
// (frozen contract section 4). Run: node --test extension/tests/
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const M = require("../lib/user_model.js");
const { fixture } = require("./helpers.js");

const byCodePoint = (a, b) => {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i].codePointAt(0) - y[i].codePointAt(0);
    if (d) return d;
  }
  return x.length - y.length;
};

test("FNV-1a 32 known values over UTF-8", () => {
  assert.equal(M.fnv1a32(""), 0x811c9dc5);
  assert.equal(M.fnv1a32("a"), 0xe40c292c);
  assert.equal(M.fnv1a32("foobar"), 0xbf9cf968);
  // Non-ASCII is hashed as UTF-8 bytes (not UTF-16 units).
  assert.equal(M.fnv1a32("é"), M.fnv1a32("é"));
  assert.notEqual(M.fnv1a32("é"), M.fnv1a32("é"));
  assert.equal(M.bucket("a"), 0xe40c292c & 0xffff);
  assert.equal(M.senderHash(" PayPal@Example.COM "), M.fnv1a32("paypal@example.com").toString(16).padStart(8, "0"));
});

test("regdom uses the fixed two-label suffix list", () => {
  assert.equal(M.regdom("mail.dhl.co.uk."), "dhl.co.uk");
  assert.equal(M.regdom("A.B.Example.COM"), "example.com");
  assert.equal(M.regdom("portal.tamm.gov.ae"), "tamm.gov.ae");
  assert.equal(M.regdom("x.y.github.io"), "github.io"); // not in the fixed list on purpose
  assert.equal(M.regdom("localhost"), "localhost");
  assert.equal(M.regdom(""), "");
});

test("tokens: NFKC, lowercase, invisible chars stripped, length in code points", () => {
  assert.deepEqual(M.tokens("Hello WORLD a"), ["hello", "world"]);
  assert.deepEqual(M.tokens("pay​pal"), ["paypal"]); // zero-width space removed before splitting
  assert.deepEqual(M.tokens("Ｐａｙ"), ["pay"]); // fullwidth -> ASCII via NFKC
  assert.deepEqual(M.tokens("مرحبا بكم"), ["مرحبا", "بكم"]);
  assert.deepEqual(M.tokens("😀😀 ok"), ["ok"]); // emoji are not letters
  const long = "a".repeat(30);
  assert.deepEqual(M.tokens(long + " " + long + "b"), [long]);
  assert.deepEqual(M.tokens("\u{1D400}\u{1D401}"), ["ab"]); // math bold -> NFKC letters
});

test("feature strings follow the contract recipe", () => {
  const s = M.featureStrings({
    from_address: "Alerts <alerts@mail.dhl.co.uk>",
    from_name: "DHL Express",
    reply_to: "x@gmail.com",
    subject: "Parcel held",
    body_text: "Pay the customs fee",
    link_domains: ["track.dhl-fee.test"],
    auth: { spf: "fail" },
    flags: ["URGENCY_LANGUAGE", { code: "BRAND_MENTION" }],
  });
  for (const want of [
    "fd:dhl.co.uk",
    "fx:0",
    "rd:diff",
    "dn:dhl",
    "dn:express",
    "s:parcel",
    "b:customs",
    "ld:dhl-fee.test",
    "a:spf=fail",
    "a:dkim=none",
    "a:dmarc=none",
    "f:URGENCY_LANGUAGE",
    "f:BRAND_MENTION",
  ]) {
    assert.ok(s.includes(want), want + " missing from " + JSON.stringify(s));
  }
  const empty = M.featureStrings({});
  assert.ok(empty.includes("rd:none") && empty.includes("fx:0") && empty.includes("a:spf=none"));
  // body is capped at 300 tokens, links at 20
  const body = Array.from({ length: 400 }, (_, i) => "w" + i).join(" ");
  const many = M.featureStrings({ body_text: body, link_domains: Array.from({ length: 30 }, (_, i) => "d" + i + ".test") });
  assert.equal(many.filter((x) => x.startsWith("b:")).length, 300);
  assert.equal(many.filter((x) => x.startsWith("ld:")).length, 20);
});

test("features match the frozen contract sample (model_features of the PayPal response)", () => {
  const req = fixture("contract/analyze_email_request.json");
  const resp = fixture("contract/analyze_email_response.json");
  if (!req || !resp) return;
  const m = req.meta;
  const input = {
    from_address: m.from_address,
    from_name: m.from_name,
    reply_to: m.reply_to,
    subject: m.subject,
    body_text: m.body_text,
    link_domains: resp.links.map((l) => l.domain),
    auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
    flags: resp.red_flags.map((f) => f.code),
  };
  assert.deepEqual(M.features(input), resp.model_features);
});

test("naive Bayes: availability threshold, sender prior, clamp, merge", () => {
  const m = M.newModel();
  assert.equal(M.predict(m, [1, 2], "a@b.c").available, false);
  for (let i = 0; i < 10; i++) {
    M.train(m, [1, 2, 3], "scam", "bad@x.test");
    M.train(m, [4, 5, 6], "ham", "friend@y.test");
  }
  const p = M.predict(m, [1, 2, 3], "bad@x.test");
  assert.equal(p.available, true);
  assert.equal(p.labels, 20);
  // hand-computed: prior 0 + 3 * [ln(11/12) - ln(1/12)] + ln(11/1)
  const logit = 3 * (Math.log(11 / 12) - Math.log(1 / 12)) + Math.log(11);
  assert.ok(Math.abs(p.p_scam - 1 / (1 + Math.exp(-logit))) < 1e-12);
  assert.equal(M.flagFor(p), "USER_MODEL_SCAM");
  assert.equal(M.flagFor(M.predict(m, [4, 5, 6], "friend@y.test")), "USER_MODEL_TRUSTED");
  // duplicated buckets count once
  assert.equal(M.predict(m, [1, 1, 2, 3, 3], null).p_scam, M.predict(m, [1, 2, 3], null).p_scam);
  const merged = M.merge(m, m);
  assert.equal(merged.classes.scam.docs, 20);
  assert.equal(merged.classes.scam.counts["1"], 20);
  assert.equal(merged.senders[M.senderHash("bad@x.test")].scam, 20);
  assert.throws(() => M.validate({ format: "nope" }));
  assert.throws(() => M.validate({ ...m, classes: { scam: { docs: -1, total: 0, counts: {} }, ham: m.classes.ham } }));
});

test("the contract's example model predicts the sample email", () => {
  const um = fixture("contract/user_model.json");
  const resp = fixture("contract/analyze_email_response.json");
  if (!um || !resp) return;
  const p = M.predict(M.validate(um), resp.model_features, resp.email.from.address);
  assert.equal(p.available, true);
  assert.ok(p.p_scam > 0.9);
});

// ---------------------------------------------------------------- shared vectors (WS-E)
const vectors = fixture("model_vectors.json");

test("model_vectors.json: feature strings and buckets", { skip: !vectors && "tests/fixtures/model_vectors.json not written yet" }, () => {
  assert.ok(Array.isArray(vectors.features) && vectors.features.length > 0);
  for (const [i, v] of vectors.features.entries()) {
    if (v.strings) {
      assert.deepEqual(M.featureStrings(v.input).slice().sort(byCodePoint), v.strings.slice().sort(byCodePoint), "strings of vector " + i);
    }
    assert.deepEqual(M.features(v.input), v.buckets, "buckets of vector " + i);
  }
});

const withoutTime = (m) => {
  const c = JSON.parse(JSON.stringify(m));
  delete c.updated_at;
  return c;
};

test("model_vectors.json: train and merge", { skip: !vectors && "tests/fixtures/model_vectors.json not written yet" }, () => {
  for (const [i, t] of (vectors.train || []).entries()) {
    const m = JSON.parse(JSON.stringify(t.start));
    for (const s of t.steps) {
      if (s.op === "untrain") M.untrain(m, s.features, s.label, s.from_address);
      else M.train(m, s.features, s.label, s.from_address);
    }
    assert.deepEqual(withoutTime(m), withoutTime(t.expect), "train vector " + i);
  }
  for (const [i, t] of (vectors.merge || []).entries()) {
    assert.deepEqual(withoutTime(M.merge(t.a, t.b)), withoutTime(t.expect), "merge vector " + i);
  }
});

test("untrain undoes train and never goes below zero", () => {
  const m = M.newModel();
  M.train(m, [1, 2, 2], "scam", "a@b.test");
  M.untrain(m, [1, 2], "scam", "a@b.test");
  assert.deepEqual(withoutTime(m), withoutTime(M.newModel()));
  M.untrain(m, [1], "ham", "a@b.test");
  assert.equal(m.classes.ham.docs, 0);
});

test("model_vectors.json: predictions within 1e-9", { skip: !vectors && "tests/fixtures/model_vectors.json not written yet" }, () => {
  assert.ok(Array.isArray(vectors.predict) && vectors.predict.length > 0);
  for (const [i, v] of vectors.predict.entries()) {
    const feats = Array.isArray(v.features) ? v.features : M.features(v.input);
    const p = M.predict(v.model, feats, v.input?.from_address ?? v.from_address);
    if (v.p_scam == null) assert.equal(p.p_scam, null, "vector " + i);
    else assert.ok(Math.abs(p.p_scam - v.p_scam) <= 1e-9, "vector " + i + ": " + p.p_scam + " vs " + v.p_scam);
    if (v.available !== undefined) assert.equal(p.available, v.available, "available of vector " + i);
  }
});
