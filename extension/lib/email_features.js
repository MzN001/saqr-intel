// SAQR-INTEL personal email model, feature extraction ("email-v1", frozen contract section 4).
//
// The SAME maths lives in Python (saqr/intel/user_model.py). Both sides must produce the exact same
// bucket numbers for the same email, otherwise a model trained in the browser would not work on the
// server (and the other way round). Shared test vectors: tests/fixtures/model_vectors.json.
//
// Runs in three places, so it uses no browser- or node-only APIs:
//   - the MV3 service worker (importScripts("lib/email_features.js"))
//   - Gmail / Outlook content scripts (listed before content/common.js in manifest.json)
//   - node --test (module.exports)
// Everything is published on globalThis.SaqrModel (user_model.js adds the model functions).

(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.SaqrModel = Object.assign(root.SaqrModel || {}, api);
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const SPEC = "email-v1";
  const BUCKETS = 65536;

  // Invisible / direction-control characters stripped before tokenising:
  // soft hyphen, combining grapheme joiner, ZWSP..RLM, LRE..RLO, word joiner..PDI, BOM.
  const STRIP_RE = /[­͏​-‏‪-‮⁠-⁩﻿]/g;
  const SPLIT_RE = /[^\p{L}\p{N}]+/u;

  // Two-label public suffixes we treat as one "TLD" (fixed list so JS and Python always agree).
  const MULTI_SUFFIXES = new Set(
    (
      "co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz co.za co.in co.jp co.kr com.br com.mx " +
      "com.tr com.sa com.eg com.kw com.qa com.bh com.om com.pk com.sg com.my com.hk com.cn gov.ae " +
      "co.ae ac.ae net.ae org.ae sch.ae mil.ae"
    ).split(" "),
  );

  const FREEMAIL = new Set(
    (
      "gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com ymail.com icloud.com " +
      "me.com aol.com proton.me protonmail.com gmx.com mail.com zoho.com yandex.com yandex.ru mail.ru"
    ).split(" "),
  );

  const MAX_BODY_TOKENS = 300;
  const MAX_LINK_DOMAINS = 20;

  const utf8 = new TextEncoder();

  /** Number of Unicode code points (not UTF-16 units: an emoji counts as 1). */
  function cpLength(s) {
    let n = 0;
    for (const _ of s) n++; // eslint-disable-line no-unused-vars
    return n;
  }

  /** NFKC -> lowercase -> strip invisible characters. */
  function clean(s) {
    return String(s == null ? "" : s)
      .normalize("NFKC")
      .toLowerCase()
      .replace(STRIP_RE, "");
  }

  /** Word tokens: letters/digits in any script, 2..30 code points long. */
  function tokens(s) {
    const out = [];
    for (const t of clean(s).split(SPLIT_RE)) {
      const n = cpLength(t);
      if (n >= 2 && n <= 30) out.push(t);
    }
    return out;
  }

  /** Registered domain with the fixed suffix list: "mail.dhl.co.uk" -> "dhl.co.uk". */
  function regdom(host) {
    let h = String(host == null ? "" : host).trim().toLowerCase();
    while (h.endsWith(".")) h = h.slice(0, -1);
    if (!h) return "";
    const labels = h.split(".");
    if (labels.length <= 2) return h;
    const lastTwo = labels.slice(-2).join(".");
    return labels.slice(MULTI_SUFFIXES.has(lastTwo) ? -3 : -2).join(".");
  }

  /** Domain part of an address ("Name <a@b.com>" or "a@b.com"); "" when there is none. */
  function domainOf(address) {
    let a = String(address == null ? "" : address).trim();
    const angle = a.match(/<([^<>]*)>/);
    if (angle) a = angle[1].trim();
    const at = a.lastIndexOf("@");
    return at >= 0 ? a.slice(at + 1).trim().toLowerCase() : "";
  }

  function isFreemail(domain) {
    return FREEMAIL.has(regdom(domain));
  }

  /** FNV-1a 32-bit over the UTF-8 bytes of s (unsigned integer). */
  function fnv1a32(s) {
    let h = 0x811c9dc5;
    for (const byte of utf8.encode(String(s))) {
      h ^= byte;
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
  }

  function bucket(s) {
    return fnv1a32(s) & 0xffff;
  }

  /** 8-digit lowercase hex FNV-1a of the lowercased sender address (model "senders" key). */
  function senderHash(fromAddress) {
    return fnv1a32(String(fromAddress == null ? "" : fromAddress).trim().toLowerCase())
      .toString(16)
      .padStart(8, "0");
  }

  function str(v) {
    return v == null ? "" : String(v);
  }

  /** The binarised feature strings of an email (a sorted list without duplicates). */
  function featureStrings(input) {
    const i = input && typeof input === "object" ? input : {};
    const auth = i.auth && typeof i.auth === "object" ? i.auth : {};
    const set = new Set();

    const fromDomain = regdom(domainOf(i.from_address));
    set.add("fd:" + fromDomain);
    set.add(isFreemail(fromDomain) ? "fx:1" : "fx:0");

    const replyDomain = regdom(domainOf(i.reply_to));
    set.add("rd:" + (!replyDomain ? "none" : replyDomain === fromDomain ? "same" : "diff"));

    for (const t of tokens(i.from_name)) set.add("dn:" + t);
    for (const t of tokens(i.subject)) set.add("s:" + t);
    for (const t of tokens(i.body_text).slice(0, MAX_BODY_TOKENS)) set.add("b:" + t);

    const links = Array.isArray(i.link_domains) ? i.link_domains : [];
    for (const d of links.slice(0, MAX_LINK_DOMAINS)) set.add("ld:" + regdom(d));

    set.add("a:spf=" + (str(auth.spf) || "none"));
    set.add("a:dkim=" + (str(auth.dkim) || "none"));
    set.add("a:dmarc=" + (str(auth.dmarc) || "none"));

    const flags = Array.isArray(i.flags) ? i.flags : [];
    for (const f of flags) {
      const code = f && typeof f === "object" ? f.code : f;
      if (code) set.add("f:" + str(code));
    }
    return Array.from(set).sort();
  }

  /** Sorted unique bucket numbers (0..65535) of an email. */
  function features(input) {
    const set = new Set(featureStrings(input).map(bucket));
    return Array.from(set).sort((a, b) => a - b);
  }

  return {
    SPEC,
    BUCKETS,
    FREEMAIL,
    MULTI_SUFFIXES,
    cpLength,
    clean,
    tokens,
    regdom,
    domainOf,
    isFreemail,
    fnv1a32,
    bucket,
    senderHash,
    featureStrings,
    features,
  };
});
