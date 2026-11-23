// Gmail adapter against a tiny fake DOM (no jsdom): ids of opened messages vs inbox rows.
// Run: node --test extension/tests/content/
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const EXT = path.resolve(__dirname, "..", "..");

/** Element stub: children are looked up by the exact selector string the adapter asks for. */
function el({ attrs = {}, kids = {}, text = "", visible = true, closest = null } = {}) {
  const n = {
    attrs,
    kids,
    textContent: text,
    parentNode: null,
    getAttribute: (k) => (k in attrs ? attrs[k] : null),
    querySelector: (s) => (kids[s] || [])[0] || null,
    querySelectorAll: (s) => kids[s] || [],
    getClientRects: () => (visible ? [1] : []),
    closest: () => closest,
  };
  for (const list of Object.values(kids)) for (const k of list) if (!k.parentNode) k.parentNode = n;
  return n;
}

function load(document) {
  const ctx = vm.createContext({ console, URL, URLSearchParams, TextEncoder, TextDecoder, setTimeout, clearTimeout });
  ctx.globalThis = ctx;
  for (const f of ["lib/email_features.js", "lib/campaign_match.js", "content/common.js", "content/gmail.js"]) {
    const file = path.join(EXT, f);
    if (fs.existsSync(file)) vm.runInContext(fs.readFileSync(file, "utf8"), ctx, { filename: file });
  }
  ctx.document = document; // set after loading so the adapter does not auto-start
  ctx.location = { pathname: "/mail/u/0/", hash: "#inbox", origin: "https://mail.google.com" };
  return ctx;
}

test("gmail: a message you sent yourself (msg-a) gets the same id as its inbox row", () => {
  const legacy = "1a2099a3e31092bc"; // real shape seen in Gmail, Nov 2026
  const body = el({ text: "hello" });
  const wrap = el({ kids: { "div.a3s": [body] } });
  body.closest = () => wrap;
  const msg = el({
    attrs: { "data-message-id": "#msg-a:r-5622019931936299714", "data-legacy-message-id": legacy },
    kids: { "div.a3s": [body] },
  });
  wrap.parentNode = msg;
  const subject = el({ text: "Lunch?" });
  const idEl = el({ attrs: { "data-legacy-last-message-id": legacy, "data-thread-id": "#thread-a:r4545779592643438002" } });
  const row = el({ kids: { "span.bog": [subject], "[data-legacy-last-message-id]": [idEl], "span.zF[email]": [el({ attrs: { email: "me@gmail.com", name: "me" } })] } });
  subject.parentNode = row;
  const main = el({ kids: { "div[role=main]": [], "div[data-message-id]": [msg], "div[role=main] tr.zA": [row] } });
  const document = el({ kids: { "div[role=main]": [main] } });
  const ctx = load(document);
  const a = ctx.SaqrGmail.adapter();
  const [m] = a.openMessages();
  const [r] = a.listRows();
  const dec = "msg-f:" + BigInt("0x" + legacy).toString(10);
  assert.equal(m.id, dec);
  assert.equal(r.id, dec);
  assert.equal(m.permId, "msg-a:r-5622019931936299714"); // "Show original" still uses the page's own id
});

test("gmail: a received message keeps its msg-f id (legacy hex = same number)", () => {
  const body = el();
  const msg = el({ attrs: { "data-message-id": "#msg-f:1854807679390727798", "data-legacy-message-id": "19bd99c1d8c03e76" }, kids: { "div.a3s": [body] } });
  body.closest = () => body;
  body.parentNode = msg;
  const main = el({ kids: { "div[data-message-id]": [msg] } });
  const ctx = load(el({ kids: { "div[role=main]": [main] } }));
  const [m] = ctx.SaqrGmail.adapter().openMessages();
  assert.equal(m.id, "msg-f:1854807679390727798");
  assert.equal(m.permId, "msg-f:1854807679390727798");
});
