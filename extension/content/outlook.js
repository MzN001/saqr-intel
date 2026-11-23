// SAQR-INTEL | Outlook on the web adapter (outlook.live.com, outlook.office.com, outlook.office365.com,
// outlook.cloud.microsoft). content/common.js does the UI and the scanning.
//
// Outlook can show its UI in Arabic, so we NEVER match aria-label or visible UI words. Only
// language-independent anchors are used: ARIA roles, data-convid, title attributes that hold an
// e-mail address, and the ItemId in the URL. Outlook gives web pages no easy way to read the original
// headers (its API needs an MSAL token the page keeps encrypted), so Outlook scans use the visible
// message (banner chip: "headers not verified") unless the USER opens "View message source": that
// dialog's text is then read and the message is rescanned with real SPF/DKIM/DMARC. Inbox rows only get
// the quick local checks (badge "open to scan fully").
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
    // [role=main] is the READING PANE only; the message list is a sibling [role=complementary].
    main: ["[role=main]", "#MainModule", "#app"],
    app: ["#MainModule", "#mainApp", "#app", "body"], // observed for SPA changes: list + reading pane
    rows: ["[role=listbox] [role=option][data-convid]", "[role=option][data-convid]", "[role=listitem][data-convid]"],
    selectedRow: ["[role=option][data-convid][aria-selected=true]", "[data-convid][aria-selected=true]"],
    // Live DOM 2026-11: div#UniqueMessageBody_N[role=document]; the role is added late, so the id is the
    // fallback. (.allowTextSelection also matches the SUBJECT container: never use it.)
    body: ["[role=main] [role=document]", "[role=document]", "[role=main] [id^='UniqueMessageBody']"],
    heading: ["[role=heading][aria-level='2']", "[role=heading][aria-level='1']", "[role=heading]"],
    // Live DOM 2026-11: span#CONV_<id>_SUBJECT[role=heading] above the thread, span#MSG_<id>_FROM[role=heading]
    // per message whose text is "Name<address>" (or only "Name" for contacts / yourself).
    subject: ["[role=heading][id$='_SUBJECT']", "[role=heading][aria-level='2']", "[role=heading][aria-level='1']"],
    fromHeading: ["[role=heading][id$='_FROM']"],
    titled: ["[title]"],
    // "View message source" (opened by the user): a modal [role=dialog] whose only text leaf is the original.
    sourceDialog: ["[role=dialog][aria-modal=true]", "[role=dialog]"],
    attachmentTitles: ["[role=listbox] [title]", "[role=list] [title]", "[role=option] [title]"],
  };

  const HOSTS = ["outlook.live.com", "outlook.office.com", "outlook.office365.com", "outlook.cloud.microsoft"];
  const EMAIL_ONLY = /^\s*<?([A-Za-z0-9._%+\-À-\uffff]+@[A-Za-z0-9.\-À-\uffff]+\.[A-Za-zÀ-\uffff]{2,})>?\s*$/;
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

  /** Lower-cased address of the first From: header of a raw source, or "". */
  function rawFromAddress(raw) {
    const head = String(raw || "").split(/\r?\n\r?\n/, 1)[0];
    const m = head.match(/^From:[ \t]*((?:.*)(?:\r?\n[ \t]+.*)*)/im);
    if (!m) return "";
    const v = m[1].replace(/\r?\n[ \t]+/g, " ");
    const a = v.match(/<\s*([^<>\s]+@[^<>\s]+)\s*>/) || v.match(/([^\s<>"]+@[^\s<>"]+)/);
    return a ? a[1].toLowerCase() : "";
  }

  function looksLikeFileName(s) {
    return FILE_NAME.test(String(s || "").trim());
  }

  /**
   * Inbox row: which text leaf is the subject? leaves = [{text, title, sender}] in document order.
   * Live DOM: sender span has title=<address>, the date span has a title (full date, words in any
   * language), the subject and preview spans have NO title. Subject = first untitled leaf after the sender.
   */
  function rowSubjectIndex(leaves) {
    const list = leaves || [];
    let after = !list.some((l) => l && l.sender);
    for (let i = 0; i < list.length; i++) {
      const l = list[i] || {};
      if (l.sender) {
        after = true;
        continue;
      }
      if (after && String(l.text || "").trim() && !String(l.title || "").trim()) return i;
    }
    return -1;
  }

  // ---------------------------------------------------------------------------------------------
  // Adapter (browser only)
  // ---------------------------------------------------------------------------------------------
  function adapter() {
    const M = root.SaqrMail;
    const hits = {};
    const counts = { rows: 0, messages: 0 };
    const main = () => M.pick(document, SELECTORS.main, hits, "main");
    const app = () => M.pick(document, SELECTORS.app, hits, "app");

    function senderIn(scope) {
      for (const n of M.pickAll(scope, SELECTORS.titled)) {
        const a = addressFromTitle(n.getAttribute("title"), n.textContent);
        if (a) return { el: n, from_name: a.name, from_address: a.address };
      }
      return { el: null, from_name: "", from_address: "" };
    }

    /** Text-bearing elements of a row in document order (no buttons, avatars, checkboxes). */
    function rowLeaves(row, senderEl) {
      const out = [];
      for (const n of row.querySelectorAll("span, div")) {
        // Only look INSIDE the row: Outlook sets aria-hidden on the whole app while a dialog is open.
        const skip = n.closest("button, [role=button], [role=img], [role=checkbox], [aria-hidden=true]");
        if (skip && skip !== row && row.contains(skip)) continue;
        let own = "";
        for (const c of n.childNodes) if (c.nodeType === 3) own += c.nodeValue;
        if (!own.trim()) continue;
        out.push({ el: n, text: own.trim(), title: n.getAttribute("title") || "", sender: n === senderEl || (!!senderEl && senderEl.contains(n)) });
      }
      return out;
    }

    function listRows() {
      const scope = app() || main();
      if (!scope) return [];
      const rows = M.pickAll(scope, SELECTORS.rows, hits, "rows").filter(M.isVisible);
      counts.rows = rows.length;
      const out = [];
      for (const row of rows) {
        const convid = row.getAttribute("data-convid");
        if (!convid) continue;
        const sender = senderIn(row);
        hits.rowSender = sender.el ? 0 : -1;
        const leaves = rowLeaves(row, sender.el);
        const si = rowSubjectIndex(leaves);
        const subjectEl = si >= 0 ? leaves[si].el : null;
        hits.rowSubject = subjectEl ? 0 : -1;
        const text = String(row.innerText || row.textContent || "").replace(/\s+/g, " ").trim();
        const meta = {
          provider: "outlook",
          from_name: sender.from_name,
          from_address: sender.from_address,
          reply_to: null,
          subject: subjectEl ? String(subjectEl.textContent || "").trim().slice(0, 500) : "",
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

    /**
     * The original source when the USER opened "View message source" (read-only; nothing is clicked for
     * them). OWA's own API needs an MSAL token the page keeps encrypted (cookie-only GetItem = 401), so
     * this is the only safe way to get real headers; otherwise scans stay DOM-only.
     */
    function rawFromPage() {
      for (const d of M.pickAll(document, SELECTORS.sourceDialog)) {
        if (!M.isVisible(d)) continue;
        for (const n of d.querySelectorAll("div, pre, textarea")) {
          if (n.children.length) continue;
          const raw = n.tagName === "TEXTAREA" ? n.value : n.textContent;
          if (raw && raw.length > 200 && /^[A-Za-z][A-Za-z0-9-]*:/.test(raw) && M.util.looksLikeRawEmail(raw)) {
            return { raw, from: rawFromAddress(raw) };
          }
        }
      }
      return null;
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

    /** Sender of an open message: a titled address, else the FROM heading text "Name<address>",
     *  else (contacts / yourself show only a name) the selected inbox row's sender if the name matches. */
    function messageSender(rootEl) {
      const s = senderIn(rootEl);
      if (s.el) return Object.assign(s, { how: 0 });
      const fh = M.pick(rootEl, SELECTORS.fromHeading);
      const text = fh ? String(fh.textContent || "").replace(/\s+/g, " ").trim() : "";
      const a = text ? addressFromTitle("", text) : null;
      if (a) return { el: fh, from_name: a.name, from_address: a.address, how: 1 };
      const sel = M.pick(document, SELECTORS.selectedRow);
      const rs = sel ? senderIn(sel) : null;
      if (rs && rs.el && (!text || text === rs.from_name || text === String(rs.el.textContent || "").trim())) {
        return { el: rs.el, from_name: text || rs.from_name, from_address: rs.from_address, how: 2 };
      }
      return { el: null, from_name: text, from_address: "", how: -1 };
    }

    function messageMeta(rootEl, body) {
      const m = main();
      const heading = M.pick(m || rootEl, SELECTORS.subject, hits, "subject") || M.pick(rootEl, SELECTORS.heading, hits, "heading");
      const sender = messageSender(rootEl);
      hits.msgSender = sender.how;
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
      observeRoot: () => app() || main(),
      listRows,
      openMessages,
      selectedRowId,
      isSpamView: () => isJunkPath(location.pathname),
      rawFromPage,
      health: () => ({ hits: Object.assign({}, hits), counts: Object.assign({}, counts), itemId: !!itemIdFromUrl(location.href) }),
    };
  }

  return { SELECTORS, HOSTS, isOutlookHost, itemIdFromUrl, isJunkPath, addressFromTitle, looksLikeFileName, rowSubjectIndex, rawFromAddress, adapter };
});
