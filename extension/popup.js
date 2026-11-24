// Saqr toolbar popup: this tab's verdict (one line), scan-this-tab, settings, server address and demo pages.

const DEFAULT_API = globalThis.SaqrConfig.DEFAULT_API; // lib/config.js (loaded first by popup.html)
const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);

const uiLang = (chrome.i18n?.getUILanguage?.() || navigator.language || "en").toLowerCase();
const LANG = uiLang.startsWith("ar") ? "ar" : "en";

const STR = {
  thisTab: ["This tab", "هذه الصفحة"],
  autoOn: ["Every page you open is checked automatically.", "يتم فحص كل صفحة تفتحها تلقائياً."],
  scanNow: ["Scan this tab", "افحص هذه الصفحة"],
  scanning: ["Scanning…", "جارٍ الفحص…"],
  emailShield: ["Email Shield and settings", "درع البريد والإعدادات"],
  emailState: ["Gmail and Outlook are checked when you open an email.", "تُفحص رسائل Gmail و Outlook عند فتحها."],
  emailOff: ["Automatic email checks are off. Use the Saqr button in the email.", "الفحص التلقائي متوقف. استخدم زر صقر في الرسالة."],
  yourAi: ["Your AI: {0}", "الذكاء الاصطناعي الخاص بك: {0}"],
  connection: ["Connection and demo", "الاتصال والعرض التجريبي"],
  save: ["Save", "حفظ"],
  demoTamm: ["Demo: fake TAMM fine", "تجربة: مخالفة TAMM مزيفة"],
  demoPost: ["Demo: fake Emirates Post", "تجربة: بريد الإمارات مزيف"],
  report: ["Report fraud: Aman 8002626 · SMS 2828", "للإبلاغ عن احتيال: أمان 8002626 · رسالة 2828"],
  checking: ["Checking…", "جارٍ التحقق…"],
  on: ["Protection on", "الحماية تعمل"],
  off: ["Offline", "غير متصل"],
  connected: ["Connected to Saqr · {0}", "متصل بصقر · {0}"],
  rules: ["rules engine", "محرك القواعد"],
  ai: ["AI: {0}", "ذكاء اصطناعي: {0}"],
  offline: ["Server waking up or offline. Try again in 30 s.", "الخادم غير متصل حالياً. حاول بعد 30 ثانية."],
  notScanned: ["Not scanned yet", "لم يتم الفحص بعد"],
  browserPage: ["Browser page (not scanned)", "صفحة المتصفح (لا تُفحص)"],
  danger: ["Dangerous: blocked", "خطير: تم الحظر"],
  warn: ["Suspicious: be careful", "مشبوه: كن حذراً"],
  safe: ["No major red flags", "لا توجد مؤشرات خطر كبيرة"],
  impersonating: ["Pretends to be {0}", "ينتحل صفة {0}"],
  blockedMsg: ["Dangerous site: this tab has been blocked.", "موقع خطير: تم حظر هذه الصفحة."],
  scanFailed: ["Scan failed: {0}", "فشل الفحص: {0}"],
  saved: ["Saved: {0}", "تم الحفظ: {0}"],
};
const t = (key, ...args) => {
  const pair = STR[key] || [key, key];
  return (LANG === "ar" ? pair[1] : pair[0]).replace(/\{(\d+)\}/g, (_, i) => (args[i] == null ? "" : String(args[i])));
};

const INK = { danger: "ink-scam", warn: "ink-suspicious", safe: "ink-safe" };

let activeTab = null;

function applyLang() {
  document.documentElement.lang = LANG;
  document.documentElement.dir = LANG === "ar" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((n) => (n.textContent = t(n.dataset.i18n)));
  $("tab-title").textContent = t("notScanned");
  $("status-short").textContent = t("checking");
  $("status-text").textContent = t("checking");
}

function toneOf(v) {
  if (v.verdict === "HIGH-RISK SCAM" || v.score >= 70) return "danger";
  if (v.verdict === "SUSPICIOUS" || v.score >= 30) return "warn";
  return "safe";
}

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function showMsg(id, text, ok = true) {
  const el = $(id);
  el.textContent = text;
  el.classList.toggle("err", !ok);
  el.classList.remove("hidden");
}

function renderVerdict(v) {
  const title = $("tab-title");
  if (!v) {
    title.textContent = t("notScanned");
    title.className = "tab-title";
    $("tab-score").textContent = "";
    return;
  }
  const tone = toneOf(v);
  title.textContent = t(tone);
  title.className = `tab-title ${INK[tone]}`;
  $("tab-score").textContent = `${Math.max(0, Math.min(100, Number(v.score) || 0))}/100`;
  const entity = LANG === "ar" ? v.entityAr || v.entityEn : v.entityEn;
  $("tab-sub").textContent = entity && tone !== "safe" ? t("impersonating", entity) : t("autoOn");
}

async function refreshStatus() {
  const dot = $("status-dot");
  dot.className = "dot";
  $("status-text").textContent = t("checking");
  const res = await send({ type: "status" });
  $("api-url").value = res.apiBaseUrl || DEFAULT_API;
  if (res.ok) {
    dot.className = "dot on";
    $("status-short").textContent = t("on");
    const engine = res.health?.llm_engine;
    $("status-text").textContent = t("connected", engine === "rules" ? t("rules") : t("ai", engine));
  } else {
    dot.className = "dot off";
    $("status-short").textContent = t("off");
    $("status-text").textContent = t("offline");
  }
  return res;
}

async function init() {
  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = activeTab?.url || "";
  $("tab-host").textContent = hostOf(url) || t("browserPage");
  if (activeTab?.id != null) {
    const { verdict } = await send({ type: "tabVerdict", tabId: activeTab.id });
    renderVerdict(verdict);
  }
  if (!/^https?:/i.test(url)) $("scan-now").disabled = true;
  await refreshStatus();
}

$("scan-now").addEventListener("click", async () => {
  if (!activeTab?.id) return;
  const btn = $("scan-now");
  btn.disabled = true;
  btn.textContent = t("scanning");
  $("scan-msg").classList.add("hidden");
  try {
    const res = await send({ type: "scanTab", tabId: activeTab.id });
    if (!res.ok) throw new Error(res.error);
    renderVerdict(res.verdict);
    if (res.blocked) showMsg("scan-msg", t("blockedMsg"), false);
  } catch (err) {
    showMsg("scan-msg", t("scanFailed", err.message || err), false);
  } finally {
    btn.disabled = false;
    btn.textContent = t("scanNow");
  }
});

async function openDemo(slug) {
  const { apiBaseUrl } = await chrome.storage.local.get("apiBaseUrl");
  await chrome.tabs.create({ url: `${(apiBaseUrl || DEFAULT_API).replace(/\/+$/, "")}/mock-scam/${slug}` });
  window.close();
}
$("demo-tamm").addEventListener("click", () => openDemo("tamm-fine"));
$("demo-post").addEventListener("click", () => openDemo("emiratespost"));

$("open-options").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
  window.close();
});

async function refreshEmailState() {
  try {
    const s = await send({ type: "emailSettings" });
    if (!s?.ok) return;
    const parts = [s.autoScan ? t("emailState") : t("emailOff")];
    if (s.llm?.model) parts.push(t("yourAi", s.llm.model));
    $("email-state").textContent = parts.join(" ");
  } catch {
    /* keep the default text */
  }
}

$("api-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await send({ type: "setApi", url: $("api-url").value.trim() || DEFAULT_API });
  if (!res.ok) {
    showMsg("api-msg", res.error, false);
    return;
  }
  showMsg("api-msg", t("saved", res.apiBaseUrl));
  await refreshStatus();
});

applyLang();
init();
refreshEmailState();
