// A tiny HTML parser + DOM subset for the content-script tests (no jsdom, no npm deps).
// Supports what content/search.js uses: querySelector(All) with tag / #id / .class / [attr], [attr=v],
// [attr^=v], [attr*=v], [attr$=v], descendant and child (>) combinators, comma lists; closest,
// textContent, attributes, createElement, insertAdjacentElement, appendChild, remove and listeners.
"use strict";

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);
const RAW = new Set(["script", "style"]);
const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00a0" };
const decode = (s) => s.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e) =>
  e[0] === "#" ? String.fromCodePoint(e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : ENT[e] ?? m);

class Node {
  constructor(type, doc) {
    this.nodeType = type;
    this.ownerDocument = doc;
    this.parentNode = null;
    this.childNodes = [];
  }
  get parentElement() {
    return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null;
  }
  get textContent() {
    if (this.nodeType === 3) return this.data;
    return this.childNodes.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    for (const c of this.childNodes) c.parentNode = null;
    this.childNodes = [];
    if (v !== "" && v != null) this.appendChild(new Text(String(v), this.ownerDocument));
  }
  appendChild(n) {
    if (n.parentNode) n.remove();
    n.parentNode = this;
    this.childNodes.push(n);
    return n;
  }
  remove() {
    const p = this.parentNode;
    if (!p) return;
    p.childNodes.splice(p.childNodes.indexOf(this), 1);
    this.parentNode = null;
  }
  contains(n) {
    for (let c = n; c; c = c.parentNode) if (c === this) return true;
    return false;
  }
}

class Text extends Node {
  constructor(data, doc) {
    super(3, doc);
    this.data = data;
  }
}

class Element extends Node {
  constructor(tag, doc) {
    super(1, doc);
    this.localName = tag.toLowerCase();
    this.tagName = tag.toUpperCase();
    this.attrs = new Map();
    this.listeners = {};
  }
  get children() {
    return this.childNodes.filter((c) => c.nodeType === 1);
  }
  get id() {
    return this.getAttribute("id") || "";
  }
  getAttribute(k) {
    return this.attrs.has(k.toLowerCase()) ? this.attrs.get(k.toLowerCase()) : null;
  }
  setAttribute(k, v) {
    this.attrs.set(k.toLowerCase(), String(v));
  }
  removeAttribute(k) {
    this.attrs.delete(k.toLowerCase());
  }
  hasAttribute(k) {
    return this.attrs.has(k.toLowerCase());
  }
  insertAdjacentElement(pos, el) {
    const p = this.parentNode;
    if (pos === "beforeend") return this.appendChild(el);
    if (pos === "afterbegin") {
      if (el.parentNode) el.remove();
      el.parentNode = this;
      this.childNodes.unshift(el);
      return el;
    }
    if (!p) return null;
    if (el.parentNode) el.remove();
    const i = p.childNodes.indexOf(this) + (pos === "afterend" ? 1 : 0);
    el.parentNode = p;
    p.childNodes.splice(i, 0, el);
    return el;
  }
  addEventListener(type, fn, capture) {
    (this.listeners[type] ||= []).push({ fn, capture: !!capture });
  }
  removeEventListener(type, fn) {
    this.listeners[type] = (this.listeners[type] || []).filter((l) => l.fn !== fn);
  }
  focus() {
    this.ownerDocument.activeElement = this;
  }
  click() {
    for (const l of this.listeners.click || []) l.fn({ type: "click", target: this, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {} });
  }
  matches(sel) {
    return parseSelector(sel).some((chain) => matchChain(this, chain));
  }
  closest(sel) {
    const chains = parseSelector(sel);
    for (let e = this; e && e.nodeType === 1; e = e.parentNode) if (chains.some((c) => matchChain(e, c))) return e;
    return null;
  }
  querySelectorAll(sel) {
    const chains = parseSelector(sel);
    const out = [];
    const walk = (n) => {
      for (const c of n.childNodes) {
        if (c.nodeType !== 1) continue;
        if (chains.some((ch) => matchChain(c, ch))) out.push(c);
        walk(c);
      }
    };
    walk(this);
    return out;
  }
  querySelector(sel) {
    return this.querySelectorAll(sel)[0] || null;
  }
}

class Document extends Element {
  constructor() {
    super("#document", null);
    this.nodeType = 9;
    this.ownerDocument = this;
    this.activeElement = null;
  }
  get documentElement() {
    return this.children.find((c) => c.localName === "html") || null;
  }
  get body() {
    return this.querySelector("body");
  }
  createElement(tag) {
    return new Element(tag, this);
  }
  getElementById(id) {
    return this.querySelector("#" + id);
  }
}

// ----------------------------------------------------------------------------------- selectors
function parseCompound(src) {
  const c = { tag: null, id: null, classes: [], attrs: [] };
  const re = /^(\*|[a-z][a-z0-9-]*)|#([\w-]+)|\.([\w-]+)|\[\s*([\w:-]+)\s*(?:([\^*$]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]+))\s*)?\]/iy;
  let i = 0;
  while (i < src.length) {
    re.lastIndex = i;
    const m = re.exec(src);
    if (!m || m.index !== i) throw new Error("minidom: unsupported selector part " + JSON.stringify(src.slice(i)));
    if (m[1]) c.tag = m[1] === "*" ? null : m[1].toLowerCase();
    else if (m[2]) c.id = m[2];
    else if (m[3]) c.classes.push(m[3]);
    else c.attrs.push({ name: m[4].toLowerCase(), op: m[5] || null, value: m[6] ?? m[7] ?? m[8] ?? "" });
    i = re.lastIndex;
  }
  return c;
}

function splitTop(sel, ch) {
  const parts = [];
  let depth = 0, quote = null, cur = "";
  for (const x of sel) {
    if (quote) {
      if (x === quote) quote = null;
    } else if (x === '"' || x === "'") quote = x;
    else if (x === "[") depth++;
    else if (x === "]") depth--;
    else if (x === ch && depth === 0) {
      parts.push(cur);
      cur = "";
      continue;
    }
    cur += x;
  }
  parts.push(cur);
  return parts;
}

const cache = new Map();
function parseSelector(sel) {
  if (cache.has(sel)) return cache.get(sel);
  const chains = splitTop(sel, ",").map((group) => {
    const tokens = [];
    const spaced = group.trim().replace(/\s*>\s*/g, " > ");
    for (const tok of splitTop(spaced, " ").filter(Boolean)) tokens.push(tok === ">" ? ">" : parseCompound(tok));
    return tokens;
  });
  cache.set(sel, chains);
  return chains;
}

function matchCompound(el, c) {
  if (c.tag && el.localName !== c.tag) return false;
  if (c.id && el.getAttribute("id") !== c.id) return false;
  const cls = (el.getAttribute("class") || "").split(/\s+/);
  if (c.classes.some((k) => !cls.includes(k))) return false;
  for (const a of c.attrs) {
    const v = el.getAttribute(a.name);
    if (v == null) return false;
    if (a.op === "=" && v !== a.value) return false;
    if (a.op === "^=" && !v.startsWith(a.value)) return false;
    if (a.op === "*=" && !v.includes(a.value)) return false;
    if (a.op === "$=" && !v.endsWith(a.value)) return false;
  }
  return true;
}

function matchChain(el, chain, i = chain.length - 1) {
  if (!matchCompound(el, chain[i])) return false;
  if (i === 0) return true;
  if (chain[i - 1] === ">") {
    const p = el.parentElement;
    return !!p && matchChain(p, chain, i - 2);
  }
  for (let p = el.parentElement; p; p = p.parentElement) if (matchChain(p, chain, i - 1)) return true;
  return false;
}

// ----------------------------------------------------------------------------------- parser
function parseHTML(html) {
  const doc = new Document();
  let cur = doc;
  const re = /<!--[\s\S]*?-->|<!doctype[^>]*>|<\/([a-z][a-z0-9-]*)\s*>|<([a-z][a-z0-9-]*)((?:\s+[^\s=>\/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?)>|([^<]+)/giy;
  let m;
  while ((m = re.exec(html))) {
    if (m[5] != null) {
      cur.appendChild(new Text(decode(m[5]), doc));
    } else if (m[1]) {
      const tag = m[1].toLowerCase();
      for (let e = cur; e && e !== doc; e = e.parentNode) {
        if (e.localName === tag) {
          cur = e.parentNode;
          break;
        }
      }
    } else if (m[2]) {
      const el = doc.createElement(m[2]);
      const attrRe = /([^\s=>\/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
      let a;
      while ((a = attrRe.exec(m[3] || ""))) el.setAttribute(a[1], decode(a[2] ?? a[3] ?? a[4] ?? ""));
      cur.appendChild(el);
      const tag = el.localName;
      if (RAW.has(tag)) {
        const end = html.toLowerCase().indexOf("</" + tag, re.lastIndex);
        re.lastIndex = end < 0 ? html.length : html.indexOf(">", end) + 1;
      } else if (!VOID.has(tag) && !m[4]) {
        cur = el;
      }
    }
  }
  if (!doc.documentElement) {
    const root = doc.createElement("html");
    for (const c of [...doc.childNodes]) root.appendChild(c);
    doc.appendChild(root);
  }
  return doc;
}

module.exports = { parseHTML, Element, Document };
