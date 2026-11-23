// SAQR-INTEL | Outlook on the web adapter (outlook.live.com, outlook.office.com, outlook.office365.com,
// outlook.cloud.microsoft). content/common.js does the UI and the scanning.
//
// Outlook can show its UI in Arabic, so we NEVER match aria-label or visible UI words. Only
// language-independent anchors are used: ARIA roles, data-convid, title attributes that hold an
// e-mail address, and the ItemId in the URL. Outlook gives web pages no easy way to read the original
// headers, so Outlook scans use the visible message only (banner chip: "headers not verified") and
// inbox rows only get the quick local checks (badge "open to scan fully").
//
// ------------------------------------------------------------------------------------------------
// E2E agent: please verify live (could not be checked without a real Outlook session):
//   1. Inbox rows = [role=option][data-convid] inside [role=main]; the sender is an element whose
//      title attribute is the e-mail address; badges appear next to the subject.
//   2. Reading pane body = [role=main] [role=document]; the subject is a [role=heading] above it;
//      the banner appears directly above the body; ItemId is read from /id/<ItemId> in the URL.
//   3. Links in the body: Safe Links (*.safelinks.protection.outlook.com/?url=) are unwrapped
//      (originalsrc attribute preferred).
//   4. Works the same with Outlook set to Arabic and in dark mode; no aria-label is used anywhere.
//   5. Junk folder (/mail/junkemail or /mail/0/junkemail) + "learn from spam" ON → modelLabel
//      source "spam_folder" when a message is opened.
//   6. Attachment names (title attributes that look like file names) are captured.
// ------------------------------------------------------------------------------------------------

(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.SaqrOutlook = api;
  if (root.document && root.location && api.isOutlookHost(root.location.hostname) && root.SaqrMail) {
    try {
      root.SaqrMail.start(api.adapter());
    } catch (err) {
      console.debug("[SAQR] outlook start failed", String((err && err.message) || err));
    }
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  "use strict";

  const SELECTORS = {
    version: "outlook-2026-11",
    main: ["[role=main]", "#MainModule", "#app"],
    rows: ["[role=main] [role=option][data-convid]", "[role=option][data-convid]", "[role=listitem][data-convid]"],
    selectedRow: ["[role=option][data-convid][aria-selected=true]", "[data-convid][aria-selected=true]"],
    body: ["[role=main] [role=document]", "[role=document]", "[role=main] .allowTextSelection"],
    heading: ["[role=heading][aria-level='2']", "[role=heading][aria-level='1']", "[role=heading]"],
    titled: ["[title]"],
    attachmentTitles: ["[role=listbox] [title]", "[role=list] [title]", "[role=option] [title]"],
  };

  const HOSTS = ["outlook.live.com", "outlook.office.com", "outlook.office365.com", "outlook.cloud.microsoft"];
  const EMAIL_ONLY = /^\s*<?([A-Za-z0-9._%+\-À-￿]+@[A-Za-z0-9.\-À-￿]+\.[A-Za-zÀ-￿]{2,})>?\s*$/;
  const NAME_AND_EMAIL = /^(.*?)\s*<\s*([^<>\s]+@[^<>\s]+\.[^<>\s]{2,})\s*>\s*$/;
  const FILE_NAME = /^[^\\/:*?"<>|\r\n@]{1,200}\.[A-Za-z0-9]{1,6}$/;

  // ---------------------------------------------------------------------------------------------
  // Pure helpers (unit-tested)
  // ---------------------------------------------------------------------------------------------
  function isOutlookHost(host) {
    const h = String(host || "").toLowerCase();
    return HOSTS.includes(h) || h.endsWith(".cloud.microsoft") && h.startsWith("outlook.");
  }

  /** ItemId from an Outlook URL path ("/mail/0/inbox/id/AQMkAD…%3D") or ?ItemID=… */
  function itemIdFromUrl(href) {
    let u;
    try {
      u = new URL(String(href || ""), "https://outlook.live.com/");
    } catch {
      return null;
    }
    const m = u.pathname.match(/\/id\/([^/?#]+)/);
    let id = m ? m[1] : u.searchParams.get("ItemID") || u.searchParams.get("itemid");
    if (!id) return null;
    try {
      id = decodeURIComponent(id);
    } catch {
      /* keep as is */
    }
    return /^[A-Za-z0-9+/=_\-.%]{8,512}$/.test(id) ? id : null;
  }

  function isJunkPath(pathname) {
    return /\/junkemail(\/|$)/i.test(String(pathname || ""));
  }

  /** A title / text value → {name, address} when it holds an e-mail address, else null. */
  function addressFromTitle(title, text) {
    const t = String(title || "").trim();
    const x = String(text || "").trim();
    let m = t.match(EMAIL_ONLY);
    if (m) return { name: x && !EMAIL_ONLY.test(x) ? x : "", address: m[1] };
    m = t.match(NAME_AND_EMAIL) || x.match(NAME_AND_EMAIL);
    if (m) return { name: m[1].replace(/^"(.*)"$/, "$1").trim(), address: m[2] };
    return null;
  }

  function looksLikeFileName(s) {
    return FILE_NAME.test(String(s || "").trim());
  }

  // ---------------------------------------------------------------------------------------------
  // Adapter (browser only)
  // ---------------------------------------------------------------------------------------------
  function adapter() {
    const M = root.SaqrMail;
    const hits = {};
    const counts = { rows: 0, messages: 0 };
    const main = () => M.pick(document, SELECTORS.main, hits, "main");

    function senderIn(scope) {
      for (const n of M.pickAll(scope, SELECTORS.titled)) {
        const a = addressFromTitle(n.getAttribute("title"), n.textContent);
        if (a) return { el: n, from_name: a.name, from_address: a.address };
      }
      return { el: null, from_name: "", from_address: "" };
    }

    function listRows() {
      const m = main();
      if (!m) return [];
      const rows = M.pickAll(m, SELECTORS.rows, hits, "rows").filter(M.isVisible);
      counts.rows = rows.length;
      const out = [];
      for (const row of rows) {
        const convid = row.getAttribute("data-convid");
        if (!convid) continue;
        const sender = senderIn(row);
        hits.rowSender = sender.el ? 0 : -1;
        // Subject: the first titled element after the sender that is not an address or a time.
        let subjectEl = null;
        let after = !sender.el;
        for (const n of M.pickAll(row, SELECTORS.titled)) {
          if (n === sender.el) {
            after = true;
            continue;
          }
          const title = (n.getAttribute("title") || "").trim();
          if (!after || !title || addressFromTitle(title, "") || /^[\d\s/:.,\-APMapm]+$/.test(title)) continue;
          subjectEl = n;
          break;
        }
        const text = String(row.innerText || row.textContent || "").replace(/\s+/g, " ").trim();
        const meta = {
          provider: "outlook",
          from_name: sender.from_name,
          from_address: sender.from_address,
          reply_to: null,
          subject: subjectEl ? subjectEl.getAttribute("title").trim() : "",
          date: null,
          body_text: text.slice(0, 2000),
          links: [],
          attachments: [],
        };
        const anchorEl = subjectEl || sender.el;
        const badgeAnchor = anchorEl ? { parent: anchorEl.parentNode, before: anchorEl } : { parent: row, before: row.firstChild };
        out.push({ el: row, id: "conv:" + convid, meta, badgeAnchor });
      }
      return out;
    }

    /** Walk up from the body to the element that also holds the subject heading. */
    function messageRoot(body, stop) {
      let n = body.parentElement;
      for (let i = 0; n && i < 12 && n !== stop; i++, n = n.parentElement) {
        if (M.pick(n, SELECTORS.heading)) return n;
      }
      return stop || body.parentElement;
    }

    function selectedRowId() {
      const r = M.pick(document, SELECTORS.selectedRow);
      const c = r && r.getAttribute("data-convid");
      return c ? "conv:" + c : null;
    }

    function openMessages() {
      const m = main();
      if (!m) return [];
      const bodies = M.pickAll(m, SELECTORS.body, hits, "body").filter(M.isVisible);
      // Ignore a [role=document] that is really a whole list region (it would contain rows).
      const real = bodies.filter((b) => !b.querySelector("[data-convid]"));
      const itemId = itemIdFromUrl(location.href);
      const conv = selectedRowId();
      const base = itemId || conv;
      const out = [];
      real.forEach((body, i) => {
        const rootEl = messageRoot(body, m);
        // One id per expanded message (a conversation can show several bodies).
        const id = base ? (real.length > 1 ? base + "#" + i : base) : null;
        const item = { el: rootEl, id, body, bannerAnchor: { parent: body.parentNode, before: body } };
        M.lazy(item, "meta", () => messageMeta(rootEl, body)); // read only when a scan needs it
        out.push(item);
      });
      counts.messages = out.length;
      return out;
    }

    function messageMeta(rootEl, body) {
      const heading = M.pick(rootEl, SELECTORS.heading, hits, "heading");
      const sender = senderIn(rootEl);
      hits.msgSender = sender.el ? 0 : -1;
      const attachments = [];
      for (const n of M.pickAll(rootEl, SELECTORS.attachmentTitles)) {
        if (body.contains(n)) continue;
        const name = (n.getAttribute("title") || "").trim();
        if (looksLikeFileName(name) && !attachments.some((a) => a.name === name)) attachments.push({ name: name.slice(0, 255), size: 0 });
      }
      return {
        provider: "outlook",
        from_name: sender.from_name,
        from_address: sender.from_address,
        reply_to: null,
        subject: heading ? String(heading.textContent || "").trim().slice(0, 500) : "",
        date: null,
        body_text: M.bodyText(body),
        links: M.collectLinks(body, ["originalsrc", "data-originalsrc"]),
        attachments: attachments.slice(0, 50),
      };
    }

    return {
      provider: "outlook",
      label: "Outlook",
      selectorsVersion: SELECTORS.version,
      canFetchRaw: false,
      observeRoot: main,
      listRows,
      openMessages,
      selectedRowId,
      isSpamView: () => isJunkPath(location.pathname),
      health: () => ({ hits: Object.assign({}, hits), counts: Object.assign({}, counts), itemId: !!itemIdFromUrl(location.href) }),
    };
  }

  return { SELECTORS, HOSTS, isOutlookHost, itemIdFromUrl, isJunkPath, addressFromTitle, looksLikeFileName, adapter };
});
