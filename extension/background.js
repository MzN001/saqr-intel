// SAQR-INTEL | Citizen Web & Maps Scam Shield — Manifest V3 service worker.
//
// Every main-frame navigation is checked with the SAQR-INTEL backend. Dangerous sites are replaced
// by blocked.html before the user can type anything. Results are cached per site so normal
// browsing stays fast and the backend's rate limit (30 scans / minute) is respected.
//
// Email Shield (Gmail / Outlook): content/*.js capture the open email and ask this worker to scan
// it (message protocol: frozen email contract, section 5). Scans go to POST /api/analyze-email
// through a small queue, verdicts are cached per message in chrome.storage.session, and the
// personal "scam / not scam" model lives only in chrome.storage.local unless the user labels a
// scanned email (then the server's copy for this browser's random reporter id learns it too).

// Shared with the content scripts and node tests (no build step): feature hashing, personal
// model and campaign matching. Must be loaded synchronously at the top of an MV3 worker.
importScripts("lib/email_features.js", "lib/user_model.js", "lib/campaign_match.js");

const DEFAULT_API = "https://saqr-intel-api.onrender.com";
const OLD_LOCAL_DEFAULT = "http://127.0.0.1:8000";
const CHANNEL = "PC_BROWSER_EXTENSION";
const BLOCK_SCORE = 70;
const SUSPICIOUS_SCORE = 30;
const SAFE_TTL_MS = 30 * 60 * 1000;
const RISKY_TTL_MS = 10 * 60 * 1000;
const FAST_TIMEOUT_MS = 15_000;
const DEEP_TIMEOUT_MS = 75_000;
const MENU_ID = "saqr-verify";

const OFFICIAL_DOMAINS = ["adpolice.gov.ae", "tamm.abudhabi", "uaepass.ae", "emiratespost.ae"];
// + SAQR's own website + the webmail apps themselves (their emails are checked by the Email Shield).
const MAIL_HOSTS = {
  gmail: ["mail.google.com"],
  outlook: ["outlook.live.com", "outlook.office.com", "outlook.office365.com", "outlook.cloud.microsoft"],
  wip: ["mail.yahoo.com", "mail.proton.me", "www.icloud.com", "mail.aol.com", "mail.zoho.com"],
};
const SKIP_DOMAINS = ["x.com", "twitter.com", "saqr-intel.vercel.app", ...MAIL_HOSTS.gmail, ...MAIL_HOSTS.outlook, ...MAIL_HOSTS.wip];
const SKIP_HOSTPORTS = ["localhost:3000", "127.0.0.1:3000"];

const BADGE = {
  scanning: { text: "…", color: "#64748b" },
  safe: { text: "SAFE", color: "#10b981" },
  warn: { text: "!", color: "#f59e0b" },
  danger: { text: "!", color: "#ef4444" },
  off: { text: "OFF", color: "#64748b" },
};

// In-flight scans are shared so two navigations to the same site cause one backend call.
const inflight = new Map();

// ---------------------------------------------------------------------------
// Listeners — registered synchronously at the top level (required for MV3 service workers).
// ---------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener(setup);
chrome.runtime.onStartup.addListener(setup);
chrome.webNavigation.onBeforeNavigate.addListener(onBeforeNavigate);
chrome.contextMenus.onClicked.addListener(onMenuClick);
chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`tab:${tabId}`));
chrome.runtime.onMessage.addListener(onMessage);

async function setup() {
  const { apiBaseUrl } = await chrome.storage.local.get("apiBaseUrl");
  // First install, or an older install still pointing at the laptop backend: use the cloud backend.
  if (!apiBaseUrl || apiBaseUrl === OLD_LOCAL_DEFAULT) await chrome.storage.local.set({ apiBaseUrl: DEFAULT_API });
  await reporterId(); // create this browser's random reporter id once
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_ID,
      title: "Verify Link with SAQR-INTEL",
      contexts: ["link", "page", "selection"],
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
async function apiBase() {
  const { apiBaseUrl } = await chrome.storage.local.get("apiBaseUrl");
  return (apiBaseUrl || DEFAULT_API).replace(/\/+$/, "");
}

function hostMatches(host, domain) {
  return host === domain || host.endsWith(`.${domain}`);
}

function isMapsUrl(url) {
  const u = url.toLowerCase();
  return u.includes("maps.google") || u.includes("google.com/maps") || u.includes("maps.app.goo.gl");
}

function isPrivateHost(host) {
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "[::1]" ||
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    /^169\.254\./.test(host)
  );
}

function extractUrl(text) {
  if (!text) return null;
  const full = text.match(/https?:\/\/[^\s<>"']+/i);
  if (full) return full[0].replace(/[.,;:!?)\]]+$/, "");
  const bare = text.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:\/[^\s<>"']*)?/i);
  return bare ? `https://${bare[0].replace(/[.,;:!?)\]]+$/, "")}` : null;
}

/** Decide whether a navigation should be scanned at all. */
async function shouldScan(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false; // chrome://, edge://, about:, extension pages
  const host = url.hostname.toLowerCase();
  const hostPort = url.host.toLowerCase();

  if (SKIP_HOSTPORTS.includes(hostPort)) return false; // the /citizen app itself
  if (SKIP_DOMAINS.some((d) => hostMatches(host, d))) return false;
  if (OFFICIAL_DOMAINS.some((d) => hostMatches(host, d))) return false;

  const { allowlist = [] } = await chrome.storage.session.get("allowlist");
  if (allowlist.includes(host)) return false; // user chose "continue anyway" on the block page

  const api = new URL(await apiBase());
  if (hostPort === api.host.toLowerCase()) return url.pathname.startsWith("/mock-scam/"); // demo scam pages only
  return !isPrivateHost(host); // routers, intranet, dev servers
}

function cacheKey(url) {
  if (isMapsUrl(url)) return `maps:${url}`;
  const u = new URL(url);
  return u.pathname.startsWith("/mock-scam/") ? `url:${u.host}${u.pathname}` : `url:${u.hostname}`;
}

/**
 * JSON request to the backend. Errors carry .status (HTTP status, 0 = network / timeout) so callers
 * can retry on 429 (rate limit) or fall back on 400 / 422 (input the backend could not use).
 */
async function requestJson(path, { method = "POST", body, timeoutMs = FAST_TIMEOUT_MS } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(`${await apiBase()}${path}`, {
      method,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err) {
    const e = new Error(err?.name === "AbortError" ? "The SAQR server took too long to answer." : "Could not reach the SAQR server.");
    e.status = 0;
    throw e;
  } finally {
    clearTimeout(timer);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
    const e = new Error(typeof detail === "string" && detail ? detail : `Backend returned ${res.status}`);
    e.status = res.status;
    throw e;
  }
  return data;
}

function postJson(path, body, timeoutMs) {
  return requestJson(path, { method: "POST", body, timeoutMs });
}

/** Compact, UI-ready verdict (also passed to blocked.html in the URL). */
function summarise(r, url) {
  const isMaps = r.kind === "maps";
  const flags = (r.red_flags || [])
    .filter((f) => f.points > 0)
    .sort((a, b) => b.points - a.points)
    .slice(0, 6)
    .map((f) => ({ code: f.code, sev: f.severity, en: f.en, ar: f.ar }));
  return {
    url,
    kind: isMaps ? "maps" : "url",
    domain: isMaps ? r.listing?.website_domain || null : r.domain || null,
    target: isMaps ? r.listing?.name || r.listing?.website_domain || "Google Maps listing" : r.domain,
    verdict: r.verdict,
    score: r.risk_score,
    entityEn: r.impersonated_entity || null,
    entityAr: r.impersonated_entity_ar || null,
    official: r.official_domains || [],
    explanationEn: r.citizen_explanation_en || "",
    explanationAr: r.citizen_explanation_ar || "",
    flags,
    harvested: r.technical_indicators?.harvested_fields || [],
    ageHours: r.technical_indicators?.domain_age_hours ?? null,
    syndicateEn: r.syndicate?.name || null,
    syndicateAr: r.syndicate?.name_ar || null,
    scanId: r.scan_id || null,
    at: new Date().toISOString(),
  };
}

function isDangerous(v) {
  return v.verdict === "HIGH-RISK SCAM" || v.score >= BLOCK_SCORE;
}

function badgeFor(v) {
  if (isDangerous(v)) return BADGE.danger;
  if (v.verdict === "SUSPICIOUS" || v.score >= SUSPICIOUS_SCORE) return BADGE.warn;
  return BADGE.safe;
}

async function setBadge(tabId, badge) {
  if (tabId == null || tabId < 0) return;
  try {
    await chrome.action.setBadgeText({ tabId, text: badge.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
    if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" });
  } catch {
    /* tab closed */
  }
}

/**
 * Scan a URL. Fast pass first (address, domain age, known scam networks — no browser);
 * the full cloud-sandbox pass only runs when the fast pass is suspicious, or when forced.
 */
async function scan(url, { force = false } = {}) {
  const key = cacheKey(url);
  if (!force) {
    const cached = (await chrome.storage.session.get(key))[key];
    if (cached && cached.expires > Date.now()) return cached.verdict;
  }
  if (inflight.has(key)) return inflight.get(key);

  const job = (async () => {
    let verdict;
    if (isMapsUrl(url)) {
      verdict = summarise(await postJson("/api/scan-maps", { maps_url: url, interception_channel: CHANNEL }, DEEP_TIMEOUT_MS), url);
    } else {
      const base = { url, channel: "web", interception_channel: CHANNEL, device_profile: "desktop", include_screenshot: false };
      verdict = summarise(await postJson("/api/analyze-url", { ...base, run_sandbox: false, use_llm: false }, FAST_TIMEOUT_MS), url);
      if (!isDangerous(verdict) && (force || verdict.score >= SUSPICIOUS_SCORE)) {
        verdict = summarise(await postJson("/api/analyze-url", { ...base, run_sandbox: true, use_llm: true }, DEEP_TIMEOUT_MS), url);
      }
    }
    const ttl = verdict.verdict === "SAFE" ? SAFE_TTL_MS : RISKY_TTL_MS;
    await chrome.storage.session.set({ [key]: { verdict, expires: Date.now() + ttl } });
    return verdict;
  })();

  inflight.set(key, job);
  try {
    return await job;
  } finally {
    inflight.delete(key);
  }
}

function resultPageUrl(verdict, mode) {
  return `${chrome.runtime.getURL("blocked.html")}?mode=${mode}&d=${encodeURIComponent(JSON.stringify(verdict))}`;
}

async function blockTab(tabId, verdict) {
  await chrome.tabs.update(tabId, { url: resultPageUrl(verdict, "block") });
}

// ---------------------------------------------------------------------------
// Automatic navigation interceptor
// ---------------------------------------------------------------------------
async function onBeforeNavigate(details) {
  if (details.frameId !== 0) return;
  const { url, tabId } = details;
  if (!(await shouldScan(url))) return;

  await setBadge(tabId, BADGE.scanning);
  try {
    const verdict = await scan(url);
    await chrome.storage.session.set({ [`tab:${tabId}`]: verdict });

    // Only act if the tab is still on that site (the user may have navigated away meanwhile).
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (!tab) return;
    const current = tab.pendingUrl || tab.url || "";
    if (/^(chrome|edge)-extension:/.test(current)) return; // already showing a SAQR page
    if (/^https?:/i.test(current) && cacheKey(current) !== cacheKey(url)) return;

    if (isDangerous(verdict)) {
      await blockTab(tabId, verdict);
      await setBadge(tabId, BADGE.danger);
    } else {
      await setBadge(tabId, badgeFor(verdict));
    }
  } catch (err) {
    console.warn("[SAQR] scan failed", url, err);
    await setBadge(tabId, BADGE.off);
  }
}

// ---------------------------------------------------------------------------
// Right-click "Verify Link with SAQR-INTEL"
// ---------------------------------------------------------------------------
async function onMenuClick(info, tab) {
  if (info.menuItemId !== MENU_ID) return;
  const target = info.linkUrl || extractUrl(info.selectionText) || info.pageUrl;
  if (!target || !/^https?:/i.test(target)) return;

  const tabId = tab?.id;
  await setBadge(tabId, BADGE.scanning);
  try {
    const verdict = await scan(target, { force: true });
    await setBadge(tabId, badgeFor(verdict));
    const checkingThisPage = !info.linkUrl && !info.selectionText && tabId != null;
    if (checkingThisPage && isDangerous(verdict)) {
      await blockTab(tabId, verdict);
    } else {
      await chrome.tabs.create({ url: resultPageUrl(verdict, "check"), index: (tab?.index ?? 0) + 1, openerTabId: tabId });
    }
  } catch (err) {
    await setBadge(tabId, BADGE.off);
    await chrome.tabs.create({
      url: resultPageUrl({ url: target, error: String(err.message || err) }, "error"),
      index: (tab?.index ?? 0) + 1,
    });
  }
}

// ---------------------------------------------------------------------------
// Messages: popup / options / blocked pages (privileged) and the Gmail / Outlook content scripts
// ---------------------------------------------------------------------------

// Only our own extension pages may change settings, read the personal model or act on tabs.
const PRIVILEGED_TYPES = new Set([
  "setApi",
  "allowHost",
  "tabVerdict",
  "scanTab",
  "modelExport",
  "modelImport",
  "modelReset",
  "modelStats",
  "saveEmailSettings",
]);
// Content scripts on the webmail hosts may only use these.
const CONTENT_TYPES = new Set([
  "status",
  "emailScan",
  "emailVerdict",
  "openEmailVerdict",
  "openReport",
  "gmailIk",
  "campaigns",
  "modelPredict",
  "modelLabel",
  "emailSettings",
]);

function isExtensionPage(sender) {
  return (
    !!sender &&
    sender.id === chrome.runtime.id &&
    typeof sender.url === "string" &&
    sender.url.startsWith(chrome.runtime.getURL(""))
  );
}

/** "gmail" | "outlook" | "wip" | null for the page a content-script message came from. */
function mailProviderOf(sender) {
  let host = "";
  try {
    host = new URL(sender?.url || sender?.tab?.url || "").hostname.toLowerCase();
  } catch {
    return null;
  }
  for (const [provider, hosts] of Object.entries(MAIL_HOSTS)) if (hosts.includes(host)) return provider;
  return null;
}

function onMessage(msg, sender, sendResponse) {
  handleMessage(msg, sender)
    .then(sendResponse)
    .catch((err) => sendResponse({ ok: false, error: String(err?.message || err) }));
  return true; // keep the channel open for the async response
}

async function handleMessage(msg, sender) {
  if (!msg || typeof msg !== "object" || Array.isArray(msg) || typeof msg.type !== "string") {
    return { ok: false, error: "Unknown message" };
  }
  const trusted = isExtensionPage(sender);
  if (!trusted) {
    if (sender?.id !== chrome.runtime.id) return { ok: false, error: "Not allowed" };
    if (PRIVILEGED_TYPES.has(msg.type)) return { ok: false, error: "Not allowed from a web page" };
    if (!CONTENT_TYPES.has(msg.type) || !mailProviderOf(sender)) return { ok: false, error: "Not allowed" };
  }
  try {
    return await dispatch(msg, sender, trusted);
  } catch (err) {
    if (err instanceof BadInput) return { ok: false, error: err.message };
    throw err;
  }
}

async function dispatch(msg, sender, trusted) {
  switch (msg.type) {
    case "status": {
      const base = await apiBase();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);
      try {
        const res = await fetch(base + "/health", { signal: controller.signal });
        const data = await res.json();
        return { ok: res.ok && data.status === "ok", apiBaseUrl: base, health: data };
      } catch (err) {
        return { ok: false, apiBaseUrl: base, error: String(err.message || err) };
      } finally {
        clearTimeout(timer);
      }
    }
    case "setApi": {
      let parsed;
      try {
        parsed = new URL(msg.url);
      } catch {
        return { ok: false, error: "Enter a full address like http://127.0.0.1:8000" };
      }
      if (!/^https?:$/.test(parsed.protocol)) return { ok: false, error: "Address must start with http:// or https://" };
      await chrome.storage.local.set({ apiBaseUrl: parsed.origin });
      await chrome.storage.session.clear(); // cached verdicts came from the old backend
      return { ok: true, apiBaseUrl: parsed.origin };
    }
    case "tabVerdict": {
      const key = "tab:" + msg.tabId;
      return { ok: true, verdict: (await chrome.storage.session.get(key))[key] || null };
    }
    case "scanTab": {
      const tab = await chrome.tabs.get(msg.tabId);
      const url = tab.url || "";
      if (!/^https?:/i.test(url)) return { ok: false, error: "This page can't be scanned (browser or extension page)." };
      await setBadge(tab.id, BADGE.scanning);
      const verdict = await scan(url, { force: true });
      await chrome.storage.session.set({ ["tab:" + tab.id]: verdict });
      await setBadge(tab.id, badgeFor(verdict));
      if (isDangerous(verdict)) await blockTab(tab.id, verdict);
      return { ok: true, verdict, blocked: isDangerous(verdict) };
    }
    case "allowHost": {
      const host = clip(msg.host, 253, "host");
      const { allowlist = [] } = await chrome.storage.session.get("allowlist");
      if (host && !allowlist.includes(host)) allowlist.push(host);
      await chrome.storage.session.set({ allowlist });
      return { ok: true };
    }

    // ----------------------------------------------------------------- Email Shield
    case "emailScan":
      return emailScan(msg, sender, trusted);
    case "emailVerdict": {
      const { key } = emailCacheKey(msg, sender, trusted);
      const hit = await cachedEmail(key);
      return { ok: true, verdict: hit?.verdict || null, full: hit?.full || null };
    }
    case "openEmailVerdict": {
      const { key } = emailCacheKey(msg, sender, trusted);
      const hit = await cachedEmail(key);
      if (!hit) return { ok: false, error: "Scan this email first." };
      const tab = sender?.tab;
      await chrome.tabs.create({
        url: resultPageUrl(hit.verdict, "check"),
        index: tab?.index != null ? tab.index + 1 : undefined,
        openerTabId: tab?.id,
      });
      return { ok: true };
    }
    case "openReport": {
      // Content-script fallback: the cached verdict when we have it, else the (size-checked) data
      // it sent. Always "check" mode: the page only renders text, and never offers "continue".
      let verdict = null;
      if (msg.message_key != null) verdict = (await cachedEmail(emailCacheKey(msg, sender, trusted).key))?.verdict || null;
      if (!verdict) {
        const d = plainObject(msg.verdict, "verdict");
        const json = JSON.stringify(d);
        if (json.length > 30_000) bad("This report is too big to open.");
        // "official" becomes a clickable link on the page: only trust it from our own cache.
        verdict = { ...JSON.parse(json), kind: "email", url: null, official: [] };
      }
      const tab = sender?.tab;
      await chrome.tabs.create({
        url: resultPageUrl(verdict, "check"),
        index: tab?.index != null ? tab.index + 1 : undefined,
        openerTabId: tab?.id,
      });
      return { ok: true };
    }
    case "gmailIk":
      return gmailIk(sender);
    case "campaigns":
      return campaignFeed({ force: trusted && msg.force === true });
    case "modelPredict": {
      const { features, fromAddress } = modelInputOf(msg);
      const p = SaqrModel.predict(await loadModel(), features, fromAddress);
      return { ok: true, available: p.available, p_scam: p.p_scam, labels: p.labels, flag: SaqrModel.flagFor(p) };
    }
    case "modelLabel":
      return modelLabel(msg, sender, trusted);
    case "modelExport":
      return { ok: true, model: (await loadModel()) || SaqrModel.newModel() };
    case "modelImport":
      return modelImport(msg);
    case "modelReset":
      return modelReset();
    case "modelStats": {
      const m = await loadModel();
      const { labeledKeys = {} } = await chrome.storage.local.get("labeledKeys");
      return {
        ok: true,
        scam: m ? m.classes.scam.docs : 0,
        ham: m ? m.classes.ham.docs : 0,
        labels: SaqrModel.labelCount(m),
        minPerClass: SaqrModel.MIN_DOCS,
        updated_at: m ? m.updated_at : null,
        labeledMessages: Object.keys(labeledKeys).length,
      };
    }
    case "emailSettings":
      return { ok: true, ...(await publicEmailSettings()) };
    case "saveEmailSettings":
      return saveEmailSettings(msg);
    default:
      return { ok: false, error: "Unknown message" };
  }
}

// ---------------------------------------------------------------------------
// Input validation for everything a content script sends (never trust the page)
// ---------------------------------------------------------------------------
class BadInput extends Error {}

function bad(message) {
  throw new BadInput(message);
}

/** A string cut to max UTF-16 units without splitting an emoji; null/undefined -> "". */
function clip(v, max, name = "value") {
  if (v == null) return "";
  if (typeof v !== "string") bad(name + " must be text");
  if (v.length <= max) return v;
  let s = v.slice(0, max);
  const last = s.charCodeAt(s.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) s = s.slice(0, -1);
  return s;
}

function clipOrNull(v, max, name) {
  const s = clip(v, max, name);
  return s ? s : null;
}

function list(v, max, name) {
  if (v == null) return [];
  if (!Array.isArray(v)) bad(name + " must be a list");
  return v.slice(0, max);
}

function plainObject(v, name) {
  if (v == null) return {};
  if (typeof v !== "object" || Array.isArray(v)) bad(name + " must be an object");
  return v;
}

const LIMITS = {
  raw: 200_000, // contract: text 200k chars
  rawAsFile: 2_900_000, // bigger originals go as an .eml file (base64 <= 4M chars)
  html: 300_000,
  body: 200_000,
  links: 100,
  attachments: 50,
};
const PROVIDERS = new Set(["gmail", "outlook", "web"]);
const MESSAGE_KEY_RE = /^[A-Za-z0-9:_.-]{8,128}$/;

function emailCacheKey(msg, sender, trusted) {
  const key = typeof msg.message_key === "string" ? msg.message_key : "";
  if (!MESSAGE_KEY_RE.test(key)) bad("message_key is missing or invalid");
  let provider = typeof msg.provider === "string" && PROVIDERS.has(msg.provider) ? msg.provider : "web";
  if (!trusted) {
    // The page cannot pretend to be another provider: it is decided by where the message came from.
    const p = mailProviderOf(sender);
    provider = p === "gmail" || p === "outlook" ? p : "web";
  }
  return { key: "eml:" + provider + ":" + key, provider, messageKey: key };
}

function sanitizeMeta(m, provider, messageKey) {
  const meta = plainObject(m, "meta");
  return {
    provider,
    message_key: messageKey,
    from_name: clip(meta.from_name, 512, "from_name"),
    from_address: clip(meta.from_address, 320, "from_address"),
    reply_to: clipOrNull(meta.reply_to, 320, "reply_to"),
    subject: clip(meta.subject, 2000, "subject"),
    date: clipOrNull(meta.date, 200, "date"),
    body_text: clip(meta.body_text, LIMITS.body, "body_text"),
    links: list(meta.links, LIMITS.links, "links")
      .map((l) => {
        const link = plainObject(l, "link");
        return { href: clip(link.href, 4096, "link href"), text: clip(link.text, 1000, "link text") };
      })
      .filter((l) => l.href),
    attachments: list(meta.attachments, LIMITS.attachments, "attachments").map((a) => {
      const att = plainObject(a, "attachment");
      const size = Number(att.size);
      return { name: clip(att.name, 300, "attachment name"), size: Number.isFinite(size) && size > 0 ? Math.floor(size) : 0 };
    }),
  };
}

/** UTF-8 -> base64 in chunks (btoa only takes Latin-1). */
function base64Utf8(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

/** Validate an emailScan message and build the POST /api/analyze-email body. */
function buildEmailRequest(msg, sender, trusted, { reporter, llm, useUserModel = true }) {
  const { key, provider, messageKey } = emailCacheKey(msg, sender, trusted);
  if (msg.raw != null && typeof msg.raw !== "string") bad("raw must be text");
  if (msg.html != null && typeof msg.html !== "string") bad("html must be text");
  const meta = sanitizeMeta(msg.meta, provider, messageKey);
  const raw = msg.raw || "";
  const body = {
    source: "text",
    text: null,
    file_base64: null,
    file_name: null,
    html: msg.html ? clip(msg.html, LIMITS.html, "html") : null,
    meta,
    channel: "email",
    reporter_id: reporter || null,
    interception_channel: CHANNEL,
    use_llm: true,
    follow_links: true,
    use_user_model: useUserModel,
  };
  if (raw && raw.length <= LIMITS.raw) {
    body.source = "raw"; // full original (headers + body): SPF / DKIM / DMARC can be read
    body.text = raw;
  } else if (raw && raw.length <= LIMITS.rawAsFile) {
    body.source = "eml"; // too long to paste: send the original as a file
    body.file_base64 = base64Utf8(raw);
    body.file_name = "message.eml";
  }
  if (!body.text && !body.file_base64 && !meta.body_text && !meta.subject && !meta.links.length) {
    bad("This email has no text to check yet.");
  }
  if (llm) body.llm = llm;
  return { key, provider, messageKey, body };
}

// ---------------------------------------------------------------------------
// Email scan queue: "scan all visible emails" can ask for 50 scans at once, the backend allows
// 30 requests a minute per address (shared with website checks), so scans run 2 at a time and
// start at least EMAIL_SPACING_MS apart. A user who opens an email jumps the queue.
// ---------------------------------------------------------------------------
const EMAIL_TIMEOUT_MS = 150_000; // link sandbox + AI judge + a cold Render start
const EMAIL_CONCURRENCY = 2;
const EMAIL_SPACING_MS = 2_500;
const EMAIL_QUEUE_MAX = 80;
const EMAIL_RETRIES_429 = 3;
const EMAIL_TTL_MS = 12 * 60 * 60 * 1000;
const EMAIL_CACHE_MAX = 200;
const KEEPALIVE_MS = 20_000;

const emailQueue = [];
const emailInflight = new Map();
let emailActive = 0;
let emailLastStart = 0;
let emailPumpTimer = null;
let keepAliveTimer = null;

/**
 * MV3 stops an idle service worker after ~30 s even while a fetch is waiting. Any extension API
 * call resets that timer, so while email scans are running we make a cheap call every 20 s.
 */
function keepAlive(on) {
  if (on && !keepAliveTimer) {
    keepAliveTimer = setInterval(() => {
      chrome.runtime.getPlatformInfo().catch(() => {});
    }, KEEPALIVE_MS);
  } else if (!on && keepAliveTimer) {
    clearInterval(keepAliveTimer);
    keepAliveTimer = null;
  }
}

function enqueueEmail(task, { priority = false } = {}) {
  if (emailQueue.length >= EMAIL_QUEUE_MAX) {
    return Promise.reject(new BadInput("Too many emails are waiting to be checked. Try again in a minute."));
  }
  return new Promise((resolve, reject) => {
    const item = { task, resolve, reject };
    if (priority) emailQueue.unshift(item);
    else emailQueue.push(item);
    keepAlive(true);
    pumpEmailQueue();
  });
}

function pumpEmailQueue() {
  while (emailActive < EMAIL_CONCURRENCY && emailQueue.length) {
    const wait = emailLastStart + EMAIL_SPACING_MS - Date.now();
    if (wait > 0) {
      if (!emailPumpTimer) {
        emailPumpTimer = setTimeout(() => {
          emailPumpTimer = null;
          pumpEmailQueue();
        }, wait);
      }
      return;
    }
    const item = emailQueue.shift();
    emailActive += 1;
    emailLastStart = Date.now();
    Promise.resolve()
      .then(item.task)
      .then(item.resolve, item.reject)
      .finally(() => {
        emailActive -= 1;
        if (!emailActive && !emailQueue.length) keepAlive(false);
        pumpEmailQueue();
      });
  }
}

const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

async function postEmail(body) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await postJson("/api/analyze-email", body, EMAIL_TIMEOUT_MS);
    } catch (err) {
      if (err.status === 429 && attempt < EMAIL_RETRIES_429) {
        await sleepMs(15_000 * (attempt + 1)); // rate limit: wait and try again
        continue;
      }
      // The original source could not be used (e.g. an unusual format): retry with the visible email.
      if ((err.status === 400 || err.status === 422) && (body.text || body.file_base64 || body.html) && attempt === 0) {
        body = { ...body, source: "text", text: null, file_base64: null, file_name: null, html: null };
        continue;
      }
      throw err;
    }
  }
}

async function cachedEmail(key) {
  const hit = (await chrome.storage.session.get(key))[key];
  return hit && hit.expires > Date.now() ? hit : null;
}

// The cache index (oldest first) is updated one write at a time.
let emailIndexChain = Promise.resolve();
function rememberEmail(key, entry) {
  emailIndexChain = emailIndexChain
    .then(async () => {
      const { emlIndex = [] } = await chrome.storage.session.get("emlIndex");
      const index = emlIndex.filter((k) => k !== key);
      index.push(key);
      const evict = index.length > EMAIL_CACHE_MAX ? index.splice(0, index.length - EMAIL_CACHE_MAX) : [];
      if (evict.length) await chrome.storage.session.remove(evict);
      await chrome.storage.session.set({ [key]: entry, emlIndex: index });
    })
    .catch((err) => console.warn("[SAQR] email cache", err));
  return emailIndexChain;
}

async function emailScan(msg, sender, trusted) {
  const [reporter, llm, settings] = await Promise.all([reporterId(), userLlmConfig(), emailSettings()]);
  const req = buildEmailRequest(msg, sender, trusted, { reporter, llm, useUserModel: settings.useUserModel });
  if (msg.force !== true) {
    const hit = await cachedEmail(req.key);
    if (hit) return { ok: true, cached: true, verdict: hit.verdict, full: hit.full };
  }
  if (emailInflight.has(req.key)) return emailInflight.get(req.key);

  const job = enqueueEmail(
    async () => {
      const r = await postEmail(req.body);
      const verdict = summariseEmail(r, req);
      const full = fullSubset(r);
      // No automatic training here: only explicit labels (and opt-in Spam-folder learning) train.
      await rememberEmail(req.key, { verdict, full, expires: Date.now() + EMAIL_TTL_MS });
      return { ok: true, cached: false, verdict, full };
    },
    { priority: msg.priority === "high" || msg.priority === "open" },
  );
  emailInflight.set(req.key, job);
  try {
    return await job;
  } catch (err) {
    if (err instanceof BadInput) return { ok: false, error: err.message };
    return { ok: false, error: String(err?.message || err), status: err?.status ?? null };
  } finally {
    emailInflight.delete(req.key);
  }
}

function bestDkim(dkim) {
  const list = Array.isArray(dkim) ? dkim : [];
  if (list.some((d) => d.result === "pass" && d.aligned)) return "pass";
  if (list.some((d) => d.result === "pass")) return "pass (other domain)";
  return list[0]?.result || "none";
}

/** Compact, UI-ready email verdict: the shape blocked.html renders, plus email extras. */
function summariseEmail(r, req) {
  const base = summarise(r, null);
  const em = r.email || {};
  const from = em.from || {};
  const auth = r.authentication || {};
  const links = (Array.isArray(r.links) ? r.links : [])
    .slice()
    .sort((a, b) => (b.risk_score ?? -1) - (a.risk_score ?? -1) || Number(!!b.text_mismatch) - Number(!!a.text_mismatch))
    .slice(0, 8)
    .map((l) => ({
      url: String(l.url || "").slice(0, 300),
      domain: l.domain || null,
      text: String(l.display_text || "").slice(0, 120),
      mismatch: !!l.text_mismatch,
      verdict: l.verdict || null,
      score: l.risk_score ?? null,
    }));
  return {
    ...base,
    url: null,
    kind: "email",
    domain: null,
    target: r.target || [from.address, em.subject].filter(Boolean).join(" | "),
    provider: req.provider,
    messageKey: req.messageKey,
    subject: String(em.subject || req.body.meta.subject || "").slice(0, 200),
    from: {
      name: from.display_name || req.body.meta.from_name || "",
      address: from.address || req.body.meta.from_address || "",
      domain: from.domain || "",
      freemail: !!from.is_freemail,
      official: !!from.is_official,
    },
    replyTo: em.reply_to?.address || null,
    hasHeaders: !!em.has_headers,
    auth: {
      spf: auth.spf?.result || "not_checked",
      dkim: bestDkim(auth.dkim),
      dmarc: auth.dmarc?.result || "not_checked",
      dmarcPolicy: auth.dmarc?.policy || null,
      arc: auth.arc?.result || "none",
      authserv: auth.trusted_authserv || null,
    },
    unicode: (r.unicode?.findings || []).slice(0, 8).map((f) => ({
      where: f.where,
      kind: f.kind,
      sample: String(f.sample_escaped || "").slice(0, 120),
      skeleton: String(f.skeleton || "").slice(0, 120),
    })),
    campaigns: (r.campaigns || []).slice(0, 5).map((c) => ({
      id: c.id,
      titleEn: c.title_en,
      titleAr: c.title_ar,
      match: c.match,
      points: c.points,
    })),
    links,
    riskyAttachments: (r.attachments || []).filter((a) => a.risky).slice(0, 5).map((a) => ({ name: a.name, reason: a.reason })),
    notes: (r.red_flags || [])
      .filter((f) => !f.points)
      .slice(0, 4)
      .map((f) => ({ code: f.code, en: f.en, ar: f.ar })),
    engine: r.analyzer?.engine || "rules",
    userLlmError: r.analyzer?.user_llm_error || null,
    userModel: r.user_model || null,
  };
}

/** The response minus timings (the content script's detailed view). */
function fullSubset(r) {
  const keep = [
    "scan_id",
    "created_at",
    "target",
    "source",
    "risk_score",
    "verdict",
    "impersonated_entity",
    "impersonated_entity_ar",
    "official_domains",
    "citizen_explanation_en",
    "citizen_explanation_ar",
    "red_flags",
    "llm_red_flags",
    "email",
    "authentication",
    "unicode",
    "links",
    "attachments",
    "campaigns",
    "user_model",
    "model_features",
    "analyzer",
  ];
  const out = {};
  for (const k of keep) if (r[k] !== undefined) out[k] = r[k];
  return out;
}

// ---------------------------------------------------------------------------
// Settings: auto-scan, Spam-folder learning, the user's own AI (OpenAI-compatible endpoint)
// ---------------------------------------------------------------------------
const EMAIL_DEFAULTS = { autoScan: true, learnSpam: false, useUserModel: true };

async function emailSettings() {
  const { emailSettings: s = {} } = await chrome.storage.local.get("emailSettings");
  return { ...EMAIL_DEFAULTS, ...s };
}

/** The user's own AI settings for the request, or null. The key is sent per scan, never stored server-side. */
async function userLlmConfig() {
  const { userLlm } = await chrome.storage.local.get("userLlm");
  if (!userLlm?.base_url || !userLlm?.model) return null;
  return { base_url: userLlm.base_url, api_key: userLlm.api_key || "", model: userLlm.model };
}

async function publicEmailSettings() {
  const [s, { userLlm }] = await Promise.all([emailSettings(), chrome.storage.local.get("userLlm")]);
  return {
    autoScan: !!s.autoScan,
    learnSpam: !!s.learnSpam,
    useUserModel: !!s.useUserModel,
    llm: { base_url: userLlm?.base_url || "", model: userLlm?.model || "", hasKey: !!userLlm?.api_key },
    apiBase: await apiBase(),
  };
}

function validateLlm(llm, previous) {
  const o = plainObject(llm, "llm");
  const baseRaw = clip(o.base_url, 300, "AI address").trim();
  const model = clip(o.model, 120, "model name").trim();
  const key = clip(o.api_key, 500, "API key").trim();
  let base;
  try {
    base = new URL(baseRaw);
  } catch {
    bad("Enter the full AI address, for example https://api.openai.com/v1");
  }
  if (base.protocol !== "https:") bad("The AI address must start with https:// so your key stays encrypted.");
  if (base.username || base.password) bad("Do not put a password inside the AI address.");
  if (!/^[\w.:/@+-]{1,120}$/.test(model)) bad("Enter the model name, for example gpt-4o-mini");
  if (key && /\s/.test(key)) bad("The API key must not contain spaces.");
  const baseUrl = (base.origin + base.pathname).replace(/\/+$/, "");
  // Keep the saved key when the user only changed the model (the key box is left empty on purpose).
  const keepOld = !key && previous?.api_key && o.keep_key !== false && new URL(previous.base_url).host === base.host;
  return { base_url: baseUrl, model, api_key: key || (keepOld ? previous.api_key : "") };
}

async function saveEmailSettings(msg) {
  const current = await emailSettings();
  const next = { ...current };
  for (const k of ["autoScan", "learnSpam", "useUserModel"]) {
    if (msg[k] !== undefined) {
      if (typeof msg[k] !== "boolean") bad(k + " must be true or false");
      next[k] = msg[k];
    }
  }
  await chrome.storage.local.set({ emailSettings: next });
  if (msg.llm === null) {
    await chrome.storage.local.remove("userLlm");
  } else if (msg.llm !== undefined) {
    const { userLlm } = await chrome.storage.local.get("userLlm");
    await chrome.storage.local.set({ userLlm: validateLlm(msg.llm, userLlm) });
  }
  return { ok: true, ...(await publicEmailSettings()) };
}

// ---------------------------------------------------------------------------
// This browser's random reporter id (links labels to the server copy of the personal model)
// ---------------------------------------------------------------------------
let reporterIdPromise = null;
function reporterId() {
  if (!reporterIdPromise) {
    reporterIdPromise = (async () => {
      const { reporterId: saved } = await chrome.storage.local.get("reporterId");
      if (typeof saved === "string" && /^r-[0-9a-f]{32}$/.test(saved)) return saved;
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      const id = "r-" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
      await chrome.storage.local.set({ reporterId: id });
      return id;
    })().catch((err) => {
      reporterIdPromise = null;
      throw err;
    });
  }
  return reporterIdPromise;
}

// ---------------------------------------------------------------------------
// Campaign feed (GET /api/campaigns), cached 6 h in chrome.storage.local with ETag
// ---------------------------------------------------------------------------
const CAMPAIGN_TTL_MS = 6 * 60 * 60 * 1000;
const CAMPAIGN_TIMEOUT_MS = 20_000;
let campaignRefresh = null;

async function campaignFeed({ force = false } = {}) {
  const base = await apiBase();
  const { campaignCache: cache } = await chrome.storage.local.get("campaignCache");
  const sameBackend = cache && cache.apiBase === base;
  const ttl = Math.max(1, Number(cache?.feed?.ttl_hours) || 6) * 60 * 60 * 1000 || CAMPAIGN_TTL_MS;
  if (!force && sameBackend && cache.fetchedAt + ttl > Date.now()) return { ok: true, feed: cache.feed, etag: cache.etag || null };

  if (!campaignRefresh) {
    campaignRefresh = refreshCampaigns(base, sameBackend ? cache : null).finally(() => {
      campaignRefresh = null;
    });
  }
  try {
    const fresh = await campaignRefresh;
    return { ok: true, feed: fresh.feed, etag: fresh.etag || null };
  } catch (err) {
    if (sameBackend && cache.feed) return { ok: true, feed: cache.feed, etag: cache.etag || null, stale: true };
    return { ok: false, error: String(err?.message || err) };
  }
}

async function refreshCampaigns(base, cache) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CAMPAIGN_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(base + "/api/campaigns", {
      headers: cache?.etag ? { "If-None-Match": cache.etag } : {},
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 304 && cache?.feed) {
    const entry = { ...cache, fetchedAt: Date.now() };
    await chrome.storage.local.set({ campaignCache: entry });
    return entry;
  }
  if (!res.ok) throw new Error("Campaign feed returned " + res.status);
  const feed = await res.json();
  if (feed?.format !== "saqr-campaigns" || !Array.isArray(feed.campaigns) || feed.campaigns.length > 5000) {
    throw new Error("Campaign feed has an unexpected format");
  }
  const entry = { apiBase: base, feed, etag: res.headers.get("etag") || null, fetchedAt: Date.now() };
  await chrome.storage.local.set({ campaignCache: entry });
  return entry;
}

// ---------------------------------------------------------------------------
// Personal model ("email-v1"): stored in chrome.storage.local, trained only by explicit labels
// ---------------------------------------------------------------------------
const LABEL_SOURCES = new Set(["user", "verdict", "spam_folder"]);
const SCAN_ID_RE = /^[A-Z]{2,5}-\d{8}-[A-Z0-9]{4,12}$/;
const LABELED_KEYS_MAX = 3000;
let modelMemo; // undefined = not loaded yet, null = no model
let modelChain = Promise.resolve();

async function loadModel() {
  if (modelMemo !== undefined) return modelMemo;
  const { userModel } = await chrome.storage.local.get("userModel");
  try {
    modelMemo = userModel ? SaqrModel.validate(userModel) : null;
  } catch {
    modelMemo = null; // a damaged model is ignored (the user can reset it)
  }
  return modelMemo;
}

/** Run model changes one at a time (two labels arriving together must not lose a count). */
function withModel(fn) {
  const run = modelChain.then(fn);
  modelChain = run.catch(() => {});
  return run;
}

async function saveModel(model) {
  modelMemo = model;
  if (model) await chrome.storage.local.set({ userModel: model });
  else await chrome.storage.local.remove("userModel");
}

function sanitizeModelInput(v) {
  const i = plainObject(v, "input");
  const auth = plainObject(i.auth, "auth");
  return {
    from_address: clip(i.from_address, 320, "from_address"),
    from_name: clip(i.from_name, 512, "from_name"),
    reply_to: clipOrNull(i.reply_to, 320, "reply_to"),
    subject: clip(i.subject, 2000, "subject"),
    body_text: clip(i.body_text, LIMITS.body, "body_text"),
    link_domains: list(i.link_domains, LIMITS.links, "link_domains").map((d) => clip(d, 253, "link domain")),
    auth: { spf: clip(auth.spf, 20, "spf"), dkim: clip(auth.dkim, 20, "dkim"), dmarc: clip(auth.dmarc, 20, "dmarc") },
    flags: list(i.flags, 100, "flags").map((f) => clip(typeof f === "object" && f ? f.code : f, 64, "flag")),
  };
}

function sanitizeFeatures(v) {
  const arr = list(v, 5000, "features");
  if (!arr.every((b) => Number.isInteger(b) && b >= 0 && b < SaqrModel.BUCKETS)) bad("features must be bucket numbers");
  return arr;
}

/** Features + sender for modelPredict / modelLabel: precomputed buckets or a raw input. */
function modelInputOf(msg) {
  if (msg.features != null) {
    return { features: sanitizeFeatures(msg.features), fromAddress: clip(msg.from_address ?? msg.input?.from_address, 320, "from_address") };
  }
  const input = sanitizeModelInput(msg.input);
  return { features: SaqrModel.features(input), fromAddress: input.from_address };
}

async function modelLabel(msg, sender, trusted) {
  const label = msg.label;
  if (!SaqrModel.LABELS.includes(label)) bad('label must be "scam" or "ham"');
  const source = msg.source == null ? "user" : msg.source;
  if (!LABEL_SOURCES.has(source)) bad("Unknown label source");
  if (source === "spam_folder") {
    if (!(await emailSettings()).learnSpam) return { ok: false, error: "Spam-folder learning is turned off." };
    if (label !== "scam") bad("Spam-folder emails can only be labelled as scam");
  }

  // A scanned email: use exactly the features the server computed (same as the server's copy).
  let cacheHit = null;
  let messageKey = null;
  if (msg.message_key != null) {
    const k = emailCacheKey(msg, sender, trusted);
    messageKey = k.key;
    cacheHit = await cachedEmail(k.key);
  }
  let features;
  let fromAddress;
  if (cacheHit?.full?.model_features) {
    features = sanitizeFeatures(cacheHit.full.model_features);
    fromAddress = cacheHit.full.email?.from?.address || "";
  } else {
    if (msg.input == null && msg.features == null) bad("Nothing to learn from: send the email's input or features.");
    ({ features, fromAddress } = modelInputOf(msg));
  }
  if (!messageKey) messageKey = "f:" + SaqrModel.fnv1a32(features.join(",") + "|" + fromAddress).toString(16);

  const result = await withModel(async () => {
    const { labeledKeys = {} } = await chrome.storage.local.get("labeledKeys");
    const model = (await loadModel()) || SaqrModel.newModel();
    const previous = labeledKeys[messageKey];
    if (previous === label) return { ok: true, labels: SaqrModel.labelCount(model), duplicate: true };
    // The user changed their mind about this email: forget the old label first.
    if (previous === "scam" || previous === "ham") SaqrModel.untrain(model, features, previous, fromAddress);
    SaqrModel.train(model, features, label, fromAddress);
    delete labeledKeys[messageKey];
    labeledKeys[messageKey] = label;
    const keys = Object.keys(labeledKeys);
    for (const k of keys.slice(0, Math.max(0, keys.length - LABELED_KEYS_MAX))) delete labeledKeys[k];
    await saveModel(model);
    await chrome.storage.local.set({ labeledKeys });
    return { ok: true, labels: SaqrModel.labelCount(model) };
  });

  // Teach the server's copy too (used when it scans with use_user_model), best effort. The server
  // only accepts scans made with this browser's reporter id.
  const scanId = cacheHit?.full?.scan_id || (typeof msg.scan_id === "string" && SCAN_ID_RE.test(msg.scan_id) ? msg.scan_id : null);
  if (!result.duplicate && scanId && source !== "spam_folder") {
    reporterId()
      .then((rid) => postJson("/api/email-model/label", { reporter_id: rid, scan_id: scanId, label }, FAST_TIMEOUT_MS))
      .catch((err) => console.warn("[SAQR] server label failed", err?.message || err));
  }
  return result;
}

async function modelImport(msg) {
  let incoming = msg.model;
  if (typeof incoming === "string") {
    if (incoming.length > 5_000_000) bad("This file is too big to be a SAQR model.");
    try {
      incoming = JSON.parse(incoming);
    } catch {
      bad("This file is not valid JSON.");
    }
  }
  let clean;
  try {
    clean = SaqrModel.validate(incoming);
  } catch (err) {
    bad(err.message);
  }
  const replace = msg.mode === "replace";
  const merged = await withModel(async () => {
    const current = await loadModel();
    const next = replace || !current ? clean : SaqrModel.merge(current, clean);
    await saveModel(next);
    return next;
  });
  const server = await syncServer("PUT", clean, replace ? "replace" : "merge");
  return { ok: true, labels: SaqrModel.labelCount(merged), server };
}

async function modelReset() {
  await withModel(async () => {
    await saveModel(null);
    await chrome.storage.local.remove("labeledKeys");
  });
  const server = await syncServer("DELETE");
  return { ok: true, labels: 0, server };
}

/** Mirror an import / erase on the server copy of this browser's model: "ok" | "failed". */
async function syncServer(method, body, mode) {
  try {
    const rid = await reporterId();
    const query = mode ? "?mode=" + mode : "";
    await requestJson("/api/email-model/" + encodeURIComponent(rid) + query, { method, body, timeoutMs: FAST_TIMEOUT_MS });
    return "ok";
  } catch (err) {
    if (method === "DELETE" && err?.status === 404) return "ok"; // nothing stored there
    console.warn("[SAQR] model sync failed", err?.message || err);
    return "failed";
  }
}

// ---------------------------------------------------------------------------
// Gmail helper: the account's "ik" token (needed to download an email's original source with its
// SPF / DKIM / DMARC headers) is only visible to the page's own JavaScript (GLOBALS[9]).
// Reads just that one value in the Gmail tab that asked; nothing else leaves the page.
// ---------------------------------------------------------------------------
async function gmailIk(sender) {
  if (mailProviderOf(sender) !== "gmail" || sender?.tab?.id == null || !chrome.scripting?.executeScript) {
    return { ok: false, error: "Not available" };
  }
  try {
    const [res] = await chrome.scripting.executeScript({
      target: { tabId: sender.tab.id, frameIds: [sender.frameId || 0] },
      world: "MAIN",
      func: () => {
        try {
          const g = window.GLOBALS;
          return Array.isArray(g) && typeof g[9] === "string" ? g[9] : null;
        } catch {
          return null;
        }
      },
    });
    const ik = res?.result;
    return typeof ik === "string" && /^[0-9a-f]{6,16}$/i.test(ik) ? { ok: true, ik } : { ok: false, error: "Not found" };
  } catch (err) {
    return { ok: false, error: String(err?.message || err) };
  }
}
