// Saqr | Gmail adapter for the mail shield (content/common.js does the UI and the scanning).
//
// All Gmail knowledge lives in ONE versioned selector table (SELECTORS below). Gmail changes its
// obfuscated class names from time to time: when that happens, add the new selector at the FRONT of
// the list (keep the old ones as fallbacks) and bump SELECTORS.version.
//
// ------------------------------------------------------------------------------------------------
// E2E agent: please verify live (these could not be checked without a real Gmail session):
//   1. Inbox rows: tr.zA are found; each has span[email] (sender), span.bog (subject), span.y2
//      (snippet) and an element with data-legacy-last-message-id / data-thread-id.
//   2. Open message: div[data-message-id="#msg-f:<decimal>"] contains span.gD[email], div.a3s (body);
//      thread subject is h2.hP; the banner appears directly above the body (before div.ii.gt).
//   3. "Show original": GET /mail/u/<u>/?ik=<ik>&view=om&permmsgid=msg-f:<id> with cookies returns a
//      page with <pre id="raw_message_text">; ik is found (download_url / ?ik= links / GLOBALS).
//      Without ik the scan must still work from the page text (banner chip "headers not verified").
//   4. Row id: hex data-legacy-last-message-id converts to the decimal msg-f id Gmail accepts.
//   5. SPA: switching folders/threads re-paints badges and banners; no duplicates; nothing breaks
//      when Gmail is in Arabic (html[lang=ar]) or dark theme.
//   6. #spam with "learn from spam folder" ON: opening a message sends modelLabel source "spam_folder".
//   7. console shows at most a few "[SAQR] selector health" debug lines, never errors.
// ------------------------------------------------------------------------------------------------

(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.SaqrGmail = api;
  // Start only inside Gmail with the shared core loaded (node tests load this file without a DOM).
  if (root.document && root.location && root.location.hostname === "mail.google.com" && root.SaqrMail) {
    try {
      root.SaqrMail.start(api.adapter());
    } catch (err) {
      console.debug("[SAQR] gmail start failed", String((err && err.message) || err));
    }
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  "use strict";

  const SELECTORS = {
    version: "gmail-2026-11",
    main: ["div[role=main]", "div.AO"],
    // Inbox list
    rows: ["div[role=main] tr.zA", "div[role=main] [role=row]", "tr.zA"],
    rowSender: ["span.zF[email]", "span.yP[email]", "span[email]"],
    rowSubject: ["span.bog", ".y6 span:first-child", "[data-thread-id]"],
    rowSnippet: ["span.y2", ".y6 + span"],
    rowIds: ["[data-legacy-last-message-id]", "[data-thread-id]", "[data-legacy-thread-id]"],
    rowDate: ["td.xW span[title]", "span[title][aria-label]"],
    // Opened message
    message: ["div[data-message-id]", "div[data-legacy-message-id]"],
    msgSender: ["span.gD[email]", "h3 span[email]", "span[email]"],
    msgReplyTo: [],
    msgSubject: ["h2.hP", "div[role=main] h2[data-thread-perm-id]", "div[role=main] h2"],
    msgDate: ["span.g3[title]", "span[title][alt]"],
    msgBody: ["div.a3s", "div.ii.gt"],
    msgBodyWrap: [".ii.gt"],
    attachments: ["[download_url]"],
    attachmentNames: ["span.aV3", ".aQA span"],
    // Where the account's "ik" key can be read from the page (content scripts can't read page JS).
    ikSources: ["[download_url]", "a[href*='ik=']", "img[src*='ik=']", "iframe[src*='ik=']"],
  };

  // ---------------------------------------------------------------------------------------------
  // Pure helpers (unit-tested)
  // ---------------------------------------------------------------------------------------------

  /** Gmail's legacy hex id ("18c9a2b3c4d5e6f7") → the decimal "msg-f:…" id used by view=om. */
  function legacyHexToMsgId(hex) {
    const h = String(hex || "").trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]{1,16}$/.test(h)) return null;
    try {
      const dec = BigInt("0x" + h);
      return dec > 0n ? "msg-f:" + dec.toString(10) : null;
    } catch {
      return null;
    }
  }

  /** From data-message-id ("#msg-f:123" / "#msg-a:r456") and/or data-legacy-message-id (hex). */
  function permMsgId(messageId, legacyId) {
    const m = String(messageId || "").trim().replace(/^#/, "");
    if (/^msg-[af]:[A-Za-z0-9_-]+$/.test(m)) return m;
    const t = m.match(/^thread-f:(\d+)$/); // a thread id = the id of its FIRST message
    if (t) return "msg-f:" + t[1];
    return legacyId ? legacyHexToMsgId(legacyId) : null;
  }

  /** Account index from /mail/u/<n>/ (0 when absent). */
  function accountIndex(pathname) {
    const m = String(pathname || "").match(/\/mail\/u\/(\d+)(?:\/|$)/);
    return m ? Number(m[1]) : 0;
  }

  function originalUrl(u, ik, permId) {
    const q = (ik ? "ik=" + encodeURIComponent(ik) + "&" : "") + "view=om&permmsgid=" + encodeURIComponent(permId);
    return "/mail/u/" + (Number(u) || 0) + "/?" + q;
  }

  /** First ik=<hex> query value in a string (URL, download_url attribute…). */
  function ikFromText(text) {
    const m = String(text || "").match(/[?&](?:amp;)?ik=([0-9a-f]{6,16})(?=[&"'\s#]|$)/i);
    return m ? m[1] : null;
  }

  /** ik from an inline script: GLOBALS=[…] (ik is GLOBALS[9]) or an "ik":"…" pair. */
  function ikFromScript(text) {
    const s = String(text || "");
    const at = s.search(/\bGLOBALS\s*=\s*\[/);
    if (at >= 0) {
      const start = s.indexOf("[", at);
      const arr = sliceArray(s, start);
      if (arr) {
        try {
          const g = JSON.parse(arr);
          if (Array.isArray(g) && typeof g[9] === "string" && /^[0-9a-f]{6,16}$/i.test(g[9])) return g[9];
        } catch {
          /* not JSON: fall through */
        }
      }
    }
    const kv = s.match(/["']?\bik["']?\s*[:=]\s*["']([0-9a-f]{6,16})["']/i);
    return kv ? kv[1] : null;
  }

  /** The balanced [...] starting at index i (strings respected), or null. Max 200 kB scanned. */
  function sliceArray(s, i) {
    if (i < 0 || s[i] !== "[") return null;
    let depth = 0, quote = null;
    const end = Math.min(s.length, i + 200000);
    for (let k = i; k < end; k++) {
      const c = s[k];
      if (quote) {
        if (c === "\\") k++;
        else if (c === quote) quote = null;
        continue;
      }
      if (c === '"' || c === "'") quote = c;
      else if (c === "[") depth++;
      else if (c === "]" && --depth === 0) return s.slice(i, k + 1);
    }
    return null;
  }

  /**
   * The raw message from Gmail's "Show original" page HTML. We do NOT build a DOM from it (no
   * DOMParser / innerHTML: Gmail uses Trusted Types and the text is attacker-controlled): the raw
   * source is the text of <pre id="raw_message_text">, HTML-escaped, so a regex + entity decode is
   * exact. Returns {raw|null, downloadHref|null} ("Download original" link as a fallback).
   */
  function rawFromOriginalHtml(html, decodeEntities) {
    const s = String(html || "");
    const pre = s.match(/<pre\b[^>]*\bid=["']?raw_message_text["']?[^>]*>([\s\S]*?)<\/pre>/i) ||
      s.match(/<pre\b[^>]*\bclass=["']?[^"'>]*raw_message_text[^"'>]*["']?[^>]*>([\s\S]*?)<\/pre>/i);
    const raw = pre ? decodeEntities(pre[1].replace(/<[^>]*>/g, "")) : null;
    const dl = s.match(/href=["']([^"']*?view=att[^"']*?disp=comp[^"']*)["']/i);
    return { raw: raw && raw.trim() ? raw : null, downloadHref: dl ? decodeEntities(dl[1]) : null };
  }

  /** download_url="mime:name:https://…" → {mime, name, url}. */
  function parseDownloadUrl(attr) {
    const m = String(attr || "").match(/^([^:]+\/[^:]+):(.*?):(https?:\/\/.*)$/);
    return m ? { mime: m[1], name: m[2], url: m[3] } : null;
  }

  function isSpamHash(hash) {
    const h = String(hash || "").toLowerCase();
    return /^#spam(\/|$)/.test(h) || /^#search\/in(%3a|:)spam/.test(h);
  }

  // ---------------------------------------------------------------------------------------------
  // Adapter (browser only)
  // ---------------------------------------------------------------------------------------------
  function adapter() {
    const M = root.SaqrMail;
    const U = M.util;
    const hits = {};
    let ik = null;
    let ikTried = 0;
    let rawFailures = 0;
    const counts = { rows: 0, messages: 0 };

    const main = () => M.pick(document, SELECTORS.main, hits, "main");

    async function findIk() {
      if (ik) return ik;
      if (Date.now() - ikTried < 30000) return null;
      ikTried = Date.now();
      for (const sel of SELECTORS.ikSources) {
        for (const n of document.querySelectorAll(sel)) {
          const v = ikFromText(n.getAttribute("download_url") || n.getAttribute("href") || n.getAttribute("src"));
          if (v) return (ik = v);
        }
      }
      for (const s of document.querySelectorAll("script:not([src])")) {
        const v = ikFromScript(s.textContent);
        if (v) return (ik = v);
      }
      // Optional background helper (reads GLOBALS[9] in the page's MAIN world) — if offered.
      const r = await M.send({ type: "gmailIk" });
      if (r && r.ok && typeof r.ik === "string" && /^[0-9a-f]{6,16}$/i.test(r.ik)) return (ik = r.ik);
      return null;
    }

    async function fetchText(url, maxBytes) {
      const res = await fetch(url, { credentials: "include", cache: "no-store", redirect: "follow" });
      if (!res.ok) return null;
      const len = Number(res.headers.get("content-length") || 0);
      if (len && len > maxBytes) return null;
      const text = await res.text();
      return text.length > maxBytes ? null : text;
    }

    async function fetchRaw(item) {
      if (!item.permId || rawFailures >= 5) return null; // Gmail changed something: stop trying
      const key = await findIk();
      const u = accountIndex(location.pathname);
      try {
        const html = await fetchText(originalUrl(u, key, item.permId), 60 * 1024 * 1024);
        const got = rawFromOriginalHtml(html, U.decodeEntities);
        if (got.raw) {
          rawFailures = 0;
          return got.raw;
        }
        if (got.downloadHref) {
          const href = new URL(got.downloadHref, location.origin + "/mail/u/" + u + "/");
          if (href.origin === location.origin) {
            const raw = await fetchText(href.href, 60 * 1024 * 1024);
            if (raw) return raw;
          }
        }
      } catch {
        /* network / format problem: fall back to the page text */
      }
      rawFailures++;
      hits.rawOriginal = -1;
      return null;
    }

    function senderOf(n) {
      if (!n) return { from_name: "", from_address: "" };
      const address = n.getAttribute("email") || "";
      const name = n.getAttribute("name") || n.textContent || "";
      return { from_name: name.trim(), from_address: address.trim() };
    }

    function listRows() {
      const m = main();
      if (!m) return [];
      const rows = M.pickAll(m, SELECTORS.rows, hits, "rows").filter(M.isVisible);
      counts.rows = rows.length;
      const out = [];
      for (const row of rows) {
        const subjectEl = M.pick(row, SELECTORS.rowSubject, hits, "rowSubject");
        const idEl = M.pick(row, SELECTORS.rowIds, hits, "rowIds");
        if (!subjectEl || !idEl) continue;
        const permId =
          legacyHexToMsgId(idEl.getAttribute("data-legacy-last-message-id")) ||
          permMsgId(idEl.getAttribute("data-thread-id"), idEl.getAttribute("data-legacy-thread-id"));
        if (!permId) continue;
        const snippet = (M.pick(row, SELECTORS.rowSnippet, hits, "rowSnippet")?.textContent || "").replace(/^\s*[-–]\s*/, "");
        const dateEl = M.pick(row, SELECTORS.rowDate, hits, "rowDate");
        const meta = Object.assign(
          { provider: "gmail", reply_to: null, subject: subjectEl.textContent.trim(), date: dateEl ? dateEl.getAttribute("title") : null, body_text: snippet.trim(), links: [], attachments: [] },
          senderOf(M.pick(row, SELECTORS.rowSender, hits, "rowSender")),
        );
        out.push({ el: row, id: permId, permId, meta, badgeAnchor: { parent: subjectEl.parentNode, before: subjectEl } });
      }
      return out;
    }

    function openMessages() {
      const m = main();
      if (!m) return [];
      const containers = M.pickAll(m, SELECTORS.message, hits, "message");
      const out = [];
      for (const c of containers) {
        const body = M.pick(c, SELECTORS.msgBody, hits, "msgBody");
        if (!body || !M.isVisible(body)) continue; // collapsed message in a thread
        const permId = permMsgId(c.getAttribute("data-message-id"), c.getAttribute("data-legacy-message-id"));
        if (!permId) continue;
        const wrapEl = body.closest(SELECTORS.msgBodyWrap.join(",")) || body;
        // id = the legacy hex id as "msg-f:<decimal>", the same id its inbox row gets (a message you
        // sent yourself has data-message-id "msg-a:r…", which would never match its row); the fetch
        // of the original keeps the page's own permId.
        const id = legacyHexToMsgId(c.getAttribute("data-legacy-message-id")) || permId;
        const item = { el: c, id, permId, body, bannerAnchor: { parent: wrapEl.parentNode, before: wrapEl } };
        // meta (body text, links, attachments) is only read when a scan actually needs it.
        M.lazy(item, "meta", () => messageMeta(m, c, body));
        out.push(item);
      }
      counts.messages = out.length;
      return out;
    }

    function messageMeta(m, c, body) {
      const subjectEl = M.pick(m, SELECTORS.msgSubject, hits, "msgSubject");
      const dateEl = M.pick(c, SELECTORS.msgDate, hits, "msgDate");
      const attachments = [];
      for (const a of c.querySelectorAll(SELECTORS.attachments.join(","))) {
        const p = parseDownloadUrl(a.getAttribute("download_url"));
        if (p && p.name) attachments.push({ name: p.name.slice(0, 255), size: 0 });
      }
      if (!attachments.length) {
        for (const n of M.pickAll(c, SELECTORS.attachmentNames)) {
          const name = (n.textContent || "").trim();
          if (name) attachments.push({ name: name.slice(0, 255), size: 0 });
        }
      }
      return Object.assign(
        {
          provider: "gmail",
          reply_to: null,
          subject: subjectEl ? subjectEl.textContent.trim() : "",
          date: dateEl ? dateEl.getAttribute("title") : null,
          body_text: M.bodyText(body),
          links: M.collectLinks(body, []),
          attachments: attachments.slice(0, 50),
        },
        senderOf(M.pick(c, SELECTORS.msgSender, hits, "msgSender")),
      );
    }

    return {
      provider: "gmail",
      label: "Gmail",
      selectorsVersion: SELECTORS.version,
      canFetchRaw: true,
      observeRoot: main,
      listRows,
      openMessages,
      fetchRaw,
      isSpamView: () => isSpamHash(location.hash),
      health: () => ({ hits: Object.assign({}, hits), counts: Object.assign({}, counts), ik: !!ik, hash: String(location.hash).split("/")[0] }),
    };
  }

  return { SELECTORS, legacyHexToMsgId, permMsgId, accountIndex, originalUrl, ikFromText, ikFromScript, sliceArray, rawFromOriginalHtml, parseDownloadUrl, isSpamHash, adapter };
});
