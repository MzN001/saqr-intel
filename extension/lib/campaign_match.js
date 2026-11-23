// SAQR-INTEL scam-campaign matching (frozen contract section 3).
//
// Same rule as saqr/intel/campaigns.py, so an inbox row is flagged in the browser exactly when the
// server would flag the full email. Shared test vectors: tests/fixtures/campaign_vectors.json.
//
// Needs lib/email_features.js first (for regdom). Published as globalThis.SaqrCampaigns
// (service worker, content scripts) and module.exports (node --test).
//
//   matchCampaign(campaign, input) -> null | {match:"ioc"|"lure", points, matched:[...]}
//   matchFeed(feed, input)         -> [{id, title_en, title_ar, match, points, matched}]
//   input = {sender_domain, link_domains[], subject, body_text, from_name? (or display_name)}

(function (root, factory) {
  const feats =
    typeof module === "object" && module.exports ? require("./email_features.js") : root.SaqrModel;
  if (!feats || typeof feats.regdom !== "function") throw new Error("load lib/email_features.js before lib/campaign_match.js");
  const api = factory(feats);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.SaqrCampaigns = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (F) {
  "use strict";

  const IOC_POINTS = 65;
  const LURE_POINTS = 20;
  const STRIP_RE = /[­͏​-‏‪-‮⁠-⁩﻿]/g;
  // Whitespace exactly as Python's str.split() sees it (JS \s misses \x1c-\x1f and \x85).
  const SPACE_RE = /[\t\n\v\f\r\x1c-\x1f \x85\xa0  - \u2028\u2029  　]+/g;
  const reCache = new Map();

  function str(v) {
    return v == null ? "" : String(v);
  }

  function list(v) {
    return Array.isArray(v) ? v : [];
  }

  /** NFKC -> lowercase -> strip invisible characters -> collapse whitespace. */
  function norm(text) {
    return str(text)
      .normalize("NFKC")
      .toLowerCase()
      .replace(STRIP_RE, "")
      .replace(SPACE_RE, " ")
      .trim();
  }

  function escapeRe(s) {
    return s.replace(/[.*+?^$\{}()|[\]\\\/-]/g, "\\$&");
  }

  /** Does the (already normalised) phrase occur in the (normalised) text as whole words? */
  function hasPhrase(normText, normPhrase) {
    if (!normPhrase) return false;
    let re = reCache.get(normPhrase);
    if (!re) {
      // Boundary = start/end of text or a character that is not a letter/digit in any script.
      re = new RegExp("(?<![\\p{L}\\p{N}])" + escapeRe(normPhrase) + "(?![\\p{L}\\p{N}])", "u");
      if (reCache.size > 2000) reCache.clear();
      reCache.set(normPhrase, re);
    }
    return re.test(normText);
  }

  function matchCampaign(campaign, input) {
    if (!campaign || typeof campaign !== "object") return null;
    const i = input && typeof input === "object" ? input : {};
    const ind = campaign.indicators && typeof campaign.indicators === "object" ? campaign.indicators : {};

    // 1. Indicators of compromise: the sender's or a link's registered domain is a known scam domain.
    const senderIoc = new Set(list(ind.sender_domains).map((d) => str(d).toLowerCase()));
    const urlIoc = new Set(list(ind.url_domains).map((d) => str(d).toLowerCase()));
    const hits = [];
    const sd = F.regdom(i.sender_domain);
    if (sd && senderIoc.has(sd)) hits.push(sd);
    for (const d of list(i.link_domains)) {
      const r = F.regdom(d);
      if (r && urlIoc.has(r) && !hits.includes(r)) hits.push(r);
    }
    if (hits.length) return { match: "ioc", points: IOC_POINTS, matched: hits };

    // 2. Lure wording: enough of the campaign's phrases, plus its brand (if it names one).
    const text = norm(str(i.subject) + " " + str(i.body_text));
    const seen = new Set();
    const matched = [];
    for (const t of list(campaign.terms)) {
      const n = norm(t);
      if (!n || seen.has(n)) continue;
      seen.add(n);
      if (hasPhrase(text, n)) matched.push(str(t));
    }
    const minTerms = Math.max(1, Math.trunc(Number(campaign.min_terms) || 1)); // as Python: max(1, int(x or 1))
    if (!matched.length || matched.length < minTerms) return null;
    const brands = list(campaign.brands).map(norm).filter(Boolean);
    if (brands.length) {
      const name = i.from_name || i.display_name || ""; // same preference as campaigns.py
      const brandText = norm(str(i.subject) + " " + str(i.body_text) + " " + str(name));
      if (!brands.some((b) => hasPhrase(brandText, b))) return null;
    }
    return { match: "lure", points: LURE_POINTS, matched };
  }

  /** All campaigns of a feed that match, IOC matches first, in the contract's response shape. */
  function matchFeed(feed, input) {
    const out = [];
    for (const c of list(feed && feed.campaigns)) {
      const ch = list(c && c.channels);
      if (ch.length && !ch.includes("email")) continue; // SMS-only campaigns don't apply to email
      const m = matchCampaign(c, input);
      if (m) out.push({ id: str(c.id), title_en: str(c.title_en), title_ar: str(c.title_ar), ...m });
    }
    return out.sort((a, b) => b.points - a.points);
  }

  return { IOC_POINTS, LURE_POINTS, norm, hasPhrase, matchCampaign, matchFeed, regdom: F.regdom };
});
