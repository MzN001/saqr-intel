// Shared helpers for the extension's node tests (node --test extension/tests/*.test.js, no npm deps).
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const EXT = path.resolve(__dirname, "..");
const FIXTURES = path.resolve(EXT, "..", "tests", "fixtures");

/** Parsed JSON fixture, or null when another workstream has not written it yet. */
function fixture(rel) {
  const p = path.join(FIXTURES, rel);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

/** In-memory chrome.storage area with the callback-free (promise) API the worker uses. */
function storageArea() {
  const data = {};
  return {
    data,
    async get(keys) {
      if (keys == null) return structuredClone(data);
      const list = typeof keys === "string" ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys);
      const out = {};
      for (const k of list) if (k in data) out[k] = structuredClone(data[k]);
      return out;
    },
    async set(obj) {
      for (const [k, v] of Object.entries(obj)) data[k] = structuredClone(v);
    },
    async remove(keys) {
      for (const k of typeof keys === "string" ? [keys] : keys) delete data[k];
    },
    async clear() {
      for (const k of Object.keys(data)) delete data[k];
    },
  };
}

const EXT_ID = "saqrtestextensionid";
const EXT_ORIGIN = "chrome-extension://" + EXT_ID + "/";

/**
 * Load background.js (and the lib/ files it importScripts) into a fresh VM context with a minimal
 * chrome stub. fetchImpl(url, init) -> {status, headers?, body} lets each test fake the backend.
 */
function loadBackground(fetchImpl) {
  const noop = () => {};
  const listener = () => ({ addListener: noop });
  const calls = { fetch: [], tabsCreate: [] };
  const chrome = {
    runtime: {
      id: EXT_ID,
      getURL: (p) => EXT_ORIGIN + p,
      onInstalled: listener(),
      onStartup: listener(),
      onMessage: listener(),
      getPlatformInfo: async () => ({ os: "linux" }),
      openOptionsPage: noop,
    },
    storage: { local: storageArea(), session: storageArea() },
    webNavigation: { onBeforeNavigate: listener() },
    contextMenus: { onClicked: listener(), removeAll: (cb) => cb && cb(), create: noop },
    tabs: {
      onRemoved: listener(),
      create: async (o) => {
        calls.tabsCreate.push(o);
        return { id: 99 };
      },
      get: async (id) => ({ id, url: "https://example.com/" }),
      update: async () => ({}),
    },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setBadgeTextColor: async () => {} },
  };
  async function fetch(url, init = {}) {
    calls.fetch.push({ url: String(url), init });
    const r = await fetchImpl(String(url), init);
    const headers = new Map(Object.entries(r.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      headers: { get: (k) => headers.get(k.toLowerCase()) ?? null },
      json: async () => (typeof r.body === "string" ? JSON.parse(r.body) : r.body),
    };
  }
  const ctx = {
    chrome,
    fetch,
    console: { log: noop, warn: noop, error: noop, info: noop },
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    AbortController,
    URL,
    TextEncoder,
    crypto: globalThis.crypto,
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    structuredClone,
  };
  ctx.globalThis = ctx;
  ctx.self = ctx;
  vm.createContext(ctx);
  ctx.importScripts = (...files) => {
    for (const f of files) vm.runInContext(fs.readFileSync(path.join(EXT, f), "utf8"), ctx, { filename: f });
  };
  vm.runInContext(fs.readFileSync(path.join(EXT, "background.js"), "utf8"), ctx, { filename: "background.js" });
  return { ctx, chrome, calls };
}

const SENDERS = {
  gmail: { id: EXT_ID, url: "https://mail.google.com/mail/u/0/#inbox/FMfcgz", tab: { id: 7, index: 2, url: "https://mail.google.com/mail/u/0/" } },
  outlook: { id: EXT_ID, url: "https://outlook.office.com/mail/inbox/id/AAQ", tab: { id: 8, index: 0 } },
  evil: { id: EXT_ID, url: "https://evil.example/mail", tab: { id: 9, index: 0 } },
  options: { id: EXT_ID, url: EXT_ORIGIN + "options.html" },
  otherExtension: { id: "someoneelse", url: "chrome-extension://someoneelse/options.html" },
};

module.exports = { EXT, FIXTURES, fixture, loadBackground, SENDERS, EXT_ORIGIN };
