// SAQR-INTEL toolbar popup: backend status, API address, scan-this-tab and 1-click demo buttons.

const DEFAULT_API = "https://saqr-intel-api.onrender.com";
const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);

const TONE_BG = { danger: "#c8102e", warn: "#d97706", safe: "#047857", none: "#0b192c" };
const TEXT = {
  danger: ["Dangerous: blocked", "خطير: تم الحظر", "danger"],
  warn: ["Suspicious: be careful", "مشبوه: كن حذراً", "warn"],
  safe: ["No major red flags", "لا توجد مؤشرات خطر كبيرة", "safe"],
};

let activeTab = null;

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
  const gauge = $("mini-gauge");
  const circle = $("mini-value");
  const c = 2 * Math.PI * 54;
  circle.style.strokeDasharray = String(c);
  if (!v) {
    gauge.style.background = TONE_BG.none;
    circle.style.strokeDashoffset = String(c);
    $("mini-num").textContent = "–";
    return;
  }
  const tone = toneOf(v);
  const [en, ar, cls] = TEXT[tone];
  gauge.style.background = TONE_BG[tone];
  circle.style.strokeDashoffset = String(c - (Math.max(0, Math.min(100, v.score)) / 100) * c);
  $("mini-num").textContent = String(v.score);
  const badge = $("tab-badge");
  badge.textContent = v.verdict;
  badge.className = `badge ${cls}`;
  badge.style.background = "";
  $("tab-title").textContent = v.entityEn && tone !== "safe" ? `${en} · impersonating ${v.entityEn}` : en;
  $("tab-title-ar").textContent = ar;
}

async function refreshStatus() {
  const dot = $("status-dot");
  dot.className = "dot";
  $("status-text").textContent = "Checking…";
  const res = await send({ type: "status" });
  $("api-url").value = res.apiBaseUrl || DEFAULT_API;
  if (res.ok) {
    dot.className = "dot on";
    $("status-text").textContent = `Connected to SAQR-INTEL · متصل · ${res.health?.llm_engine === "rules" ? "rules engine" : `AI: ${res.health?.llm_engine}`}`;
  } else {
    dot.className = "dot off";
    $("status-text").textContent = "Backend waking up or offline. Try again in 30 s · الخادم غير متصل";
  }
  return res;
}

async function init() {
  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = activeTab?.url || "";
  $("tab-host").textContent = hostOf(url) || "Browser page (not scanned)";
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
  btn.textContent = "Scanning in the cloud… · جارٍ الفحص";
  $("scan-msg").classList.add("hidden");
  try {
    const res = await send({ type: "scanTab", tabId: activeTab.id });
    if (!res.ok) throw new Error(res.error);
    renderVerdict(res.verdict);
    if (res.blocked) showMsg("scan-msg", "Dangerous site: this tab has been blocked. · تم حظر الصفحة", false);
    else showMsg("scan-msg", `${res.verdict.verdict} · ${res.verdict.score}/100`);
  } catch (err) {
    showMsg("scan-msg", `Scan failed: ${err.message || err}`, false);
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan Current Tab Now · افحص الآن";
  }
});

async function openDemo(slug) {
  const { apiBaseUrl } = await chrome.storage.local.get("apiBaseUrl");
  await chrome.tabs.create({ url: `${(apiBaseUrl || DEFAULT_API).replace(/\/+$/, "")}/mock-scam/${slug}` });
  window.close();
}
$("demo-tamm").addEventListener("click", () => openDemo("tamm-fine"));
$("demo-post").addEventListener("click", () => openDemo("emiratespost"));

$("api-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await send({ type: "setApi", url: $("api-url").value.trim() || DEFAULT_API });
  if (!res.ok) {
    showMsg("api-msg", res.error, false);
    return;
  }
  showMsg("api-msg", `Saved: ${res.apiBaseUrl}`);
  await refreshStatus();
});

init();
