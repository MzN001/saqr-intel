// SAQR-INTEL | Citizen Web & Maps Scam Shield — Manifest V3 service worker.
//
// Every main-frame navigation is checked with the SAQR-INTEL backend. Dangerous sites are replaced
// by blocked.html before the user can type anything. Results are cached per site so normal
// browsing stays fast and the backend's rate limit (30 scans / minute) is respected.

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
const SKIP_DOMAINS = ["x.com", "twitter.com", "saqr-intel.vercel.app"]; // + SAQR's own website
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

async function postJson(path, body, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${await apiBase()}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
      throw new Error(detail || `Backend returned ${res.status}`);
    }
    return data;
  } finally {
    clearTimeout(timer);
  }
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
// Messages from popup.js and blocked.js
// ---------------------------------------------------------------------------
function onMessage(msg, sender, sendResponse) {
  handleMessage(msg)
    .then(sendResponse)
    .catch((err) => sendResponse({ ok: false, error: String(err.message || err) }));
  return true; // keep the channel open for the async response
}

async function handleMessage(msg) {
  switch (msg?.type) {
    case "status": {
      const base = await apiBase();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);
      try {
        const res = await fetch(`${base}/health`, { signal: controller.signal });
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
      const key = `tab:${msg.tabId}`;
      return { ok: true, verdict: (await chrome.storage.session.get(key))[key] || null };
    }
    case "scanTab": {
      const tab = await chrome.tabs.get(msg.tabId);
      const url = tab.url || "";
      if (!/^https?:/i.test(url)) return { ok: false, error: "This page can't be scanned (browser or extension page)." };
      await setBadge(tab.id, BADGE.scanning);
      const verdict = await scan(url, { force: true });
      await chrome.storage.session.set({ [`tab:${tab.id}`]: verdict });
      await setBadge(tab.id, badgeFor(verdict));
      if (isDangerous(verdict)) await blockTab(tab.id, verdict);
      return { ok: true, verdict, blocked: isDangerous(verdict) };
    }
    case "allowHost": {
      const { allowlist = [] } = await chrome.storage.session.get("allowlist");
      if (msg.host && !allowlist.includes(msg.host)) allowlist.push(msg.host);
      await chrome.storage.session.set({ allowlist });
      return { ok: true };
    }
    default:
      return { ok: false, error: "Unknown message" };
  }
}
