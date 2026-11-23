// Parity of lib/campaign_match.js with saqr/intel/campaigns.py (frozen contract section 3).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const C = require("../lib/campaign_match.js");
const { fixture } = require("./helpers.js");

const feed = fixture("contract/campaigns_feed.json");
const paypal = feed && feed.campaigns.find((c) => c.id === "cmp-7f3a9c21");
const post = feed && feed.campaigns.find((c) => c.id === "cmp-2d81e0b4");

test("norm: NFKC, lowercase, invisible chars stripped, whitespace collapsed", () => {
  assert.equal(C.norm("  Account​   HAS\tbeen\n\nLimited ﻿"), "account has been limited");
  assert.equal(C.norm("Ｃustoms"), "customs");
  assert.equal(C.norm("a\x1fb"), "a b"); // Python str.split() treats \x1f as whitespace
});

test("phrases match at word boundaries only (any script)", () => {
  assert.ok(C.hasPhrase("your parcel is held", "parcel"));
  assert.ok(!C.hasPhrase("your parcels are held", "parcel"));
  assert.ok(!C.hasPhrase("xparcel", "parcel"));
  assert.ok(C.hasPhrase("(parcel)", "parcel"));
  assert.ok(C.hasPhrase("ادفع رسوم جمركية الآن", "رسوم جمركية"));
  assert.ok(!C.hasPhrase("بشحنتك", "شحنتك")); // Arabic prefix letter = no boundary
  assert.ok(C.hasPhrase("pay $5.00 now", "$5.00")); // regex characters are escaped
});

test("IOC match on sender or link registered domain", { skip: !feed && "contract feed missing" }, () => {
  const r = C.matchCampaign(paypal, { sender_domain: "mail.paypal-support-center.test", link_domains: [], subject: "", body_text: "" });
  assert.deepEqual(r, { match: "ioc", points: 65, matched: ["paypal-support-center.test"] });
  const l = C.matchCampaign(post, { sender_domain: "gmail.com", link_domains: ["a.ep-parcel-fee.test", "uae-post-track.test", "x.ep-parcel-fee.test"], subject: "", body_text: "" });
  assert.deepEqual(l, { match: "ioc", points: 65, matched: ["ep-parcel-fee.test", "uae-post-track.test"] });
});

test("lure match needs min_terms and a brand", { skip: !feed && "contract feed missing" }, () => {
  const req = fixture("contract/analyze_email_request.json");
  const m = req.meta;
  const input = { sender_domain: "gmail.com", link_domains: [], subject: m.subject, body_text: m.body_text, display_name: m.from_name };
  assert.deepEqual(C.matchCampaign(paypal, input), {
    match: "lure",
    points: 20,
    matched: ["account has been limited", "confirm your identity", "restore access"],
  });
  // brand missing -> no match
  assert.equal(C.matchCampaign(paypal, { subject: "account limited", body_text: "please confirm your identity" }), null);
  // only one term -> no match
  assert.equal(C.matchCampaign(paypal, { subject: "PayPal", body_text: "restore access" }), null);
  // Arabic lure with the Arabic brand
  const ar = C.matchCampaign(post, { subject: "بريد الإمارات", body_text: "شحنتك محتجزة. ادفع رسوم جمركية" });
  assert.deepEqual(ar, { match: "lure", points: 20, matched: ["رسوم جمركية", "شحنتك"] });
  // feed helper adds titles; SMS-only campaigns are skipped
  const all = C.matchFeed(feed, input);
  assert.equal(all.length, 1);
  assert.equal(all[0].id, "cmp-7f3a9c21");
  assert.equal(all[0].title_ar, paypal.title_ar);
  const smsOnly = { ...feed, campaigns: [{ ...post, channels: ["sms"] }] };
  assert.deepEqual(C.matchFeed(smsOnly, { subject: "emirates post", body_text: "parcel redelivery" }), []);
});

// ---------------------------------------------------------------- shared vectors (WS-D)
const vectors = fixture("campaign_vectors.json");

test("campaign_vectors.json parity", { skip: !vectors && "tests/fixtures/campaign_vectors.json not written yet" }, () => {
  const list = Array.isArray(vectors) ? vectors : vectors.vectors || vectors.cases || [];
  assert.ok(list.length > 0);
  for (const [i, v] of list.entries()) {
    const got = C.matchCampaign(v.campaign, v.input);
    if (v.expect == null) {
      assert.equal(got, null, "vector " + i + (v.name ? " (" + v.name + ")" : ""));
    } else {
      assert.ok(got, "vector " + i + " should match" + (v.name ? " (" + v.name + ")" : ""));
      assert.equal(got.match, v.expect.match, "match kind of vector " + i);
      assert.deepEqual(got.matched, v.expect.matched, "matched of vector " + i);
      if (v.expect.points !== undefined) assert.equal(got.points, v.expect.points);
    }
  }
});
