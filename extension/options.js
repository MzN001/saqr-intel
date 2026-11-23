// SAQR-INTEL Email Shield settings page (opened from the popup or chrome://extensions).
// Everything goes through background.js, which only accepts these changes from extension pages.

const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);

function showMsg(id, text, ok = true) {
  const el = $(id);
  el.textContent = text;
  el.classList.toggle("err", !ok);
  el.classList.remove("hidden");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.add("hidden"), 6000);
}

async function call(msg, msgId) {
  try {
    const res = await send(msg);
    if (!res?.ok) throw new Error(res?.error || "Something went wrong");
    return res;
  } catch (err) {
    showMsg(msgId, `${err.message || err} · حدث خطأ`, false);
    return null;
  }
}

// ---------------------------------------------------------------- settings
async function loadSettings() {
  const s = await call({ type: "emailSettings" }, "scan-msg");
  if (!s) return;
  $("auto-scan").checked = !!s.autoScan;
  $("learn-spam").checked = !!s.learnSpam;
  $("llm-base").value = s.llm?.base_url || "";
  $("llm-model").value = s.llm?.model || "";
  $("llm-key").value = "";
  $("llm-key").placeholder = s.llm?.hasKey ? "Saved. Leave empty to keep it · محفوظ" : "sk-...";
}

$("auto-scan").addEventListener("change", async (e) => {
  const res = await call({ type: "saveEmailSettings", autoScan: e.target.checked }, "scan-msg");
  if (res) showMsg("scan-msg", res.autoScan ? "Emails are checked when you open them · تم التفعيل" : "Automatic checks are off · تم الإيقاف");
});

$("learn-spam").addEventListener("change", async (e) => {
  const res = await call({ type: "saveEmailSettings", learnSpam: e.target.checked }, "model-msg");
  if (res) showMsg("model-msg", res.learnSpam ? "Spam-folder learning is on · تم التفعيل" : "Spam-folder learning is off · تم الإيقاف");
});

// Same limits as background.js LLM_LIMITS and the server (saqr/intel/user_llm.py): say so, never cut silently.
const LLM_LIMITS = { baseUrl: 300, model: 100, key: 512 };

function llmTooLong(llm) {
  if (llm.base_url.length > LLM_LIMITS.baseUrl) {
    return `The AI address is too long (at most ${LLM_LIMITS.baseUrl} characters) · عنوان الخدمة طويل جداً (الحد الأقصى ${LLM_LIMITS.baseUrl} حرفاً)`;
  }
  if (llm.model.length > LLM_LIMITS.model) {
    return `The model name is too long (at most ${LLM_LIMITS.model} characters) · اسم النموذج طويل جداً (الحد الأقصى ${LLM_LIMITS.model} حرفاً)`;
  }
  if (llm.api_key.length > LLM_LIMITS.key) {
    return `The API key is too long (at most ${LLM_LIMITS.key} characters). Check that you pasted only the key · مفتاح الخدمة طويل جداً (الحد الأقصى ${LLM_LIMITS.key} حرفاً)`;
  }
  return null;
}

$("llm-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const llm = { base_url: $("llm-base").value.trim(), api_key: $("llm-key").value.trim(), model: $("llm-model").value.trim() };
  if (!llm.base_url || !llm.model) {
    showMsg("llm-msg", "Enter the AI address and the model name · أدخل العنوان واسم النموذج", false);
    return;
  }
  const tooLong = llmTooLong(llm);
  if (tooLong) {
    showMsg("llm-msg", tooLong, false);
    return;
  }
  const res = await call({ type: "saveEmailSettings", llm }, "llm-msg");
  if (!res) return;
  $("llm-key").value = "";
  $("llm-key").placeholder = res.llm.hasKey ? "Saved. Leave empty to keep it · محفوظ" : "sk-...";
  showMsg("llm-msg", `Saved. Your AI (${res.llm.model}) will be used for the next email checks · تم الحفظ`);
});

$("llm-clear").addEventListener("click", async () => {
  const res = await call({ type: "saveEmailSettings", llm: null }, "llm-msg");
  if (!res) return;
  $("llm-base").value = "";
  $("llm-model").value = "";
  $("llm-key").value = "";
  $("llm-key").placeholder = "sk-...";
  showMsg("llm-msg", "Your AI settings and key were removed · تم الحذف");
});

// ---------------------------------------------------------------- personal model
async function loadStats() {
  const s = await call({ type: "modelStats" }, "model-msg");
  if (!s) return;
  $("n-scam").textContent = String(s.scam);
  $("n-ham").textContent = String(s.ham);
  $("min-docs").textContent = String(s.minPerClass);
  const ready = s.scam >= s.minPerClass && s.ham >= s.minPerClass;
  $("n-state").textContent = ready ? "Active · يعمل" : "Learning · يتعلم";
}

$("export").addEventListener("click", async () => {
  const res = await call({ type: "modelExport" }, "model-msg");
  if (!res) return;
  const blob = new Blob([JSON.stringify(res.model, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `saqr-email-filter-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
  showMsg("model-msg", "Downloaded. Keep the file private · تم التنزيل");
});

$("import-btn").addEventListener("click", () => $("import-file").click());
$("import-file").addEventListener("change", async (e) => {
  const f = e.target.files?.[0];
  e.target.value = "";
  if (!f) return;
  if (f.size > 5_000_000) {
    showMsg("model-msg", "This file is too big to be a SAQR filter · الملف كبير جداً", false);
    return;
  }
  const res = await call({ type: "modelImport", model: await f.text(), mode: "merge" }, "model-msg");
  if (!res) return;
  showMsg(
    "model-msg",
    `Loaded and added to your filter (${res.labels} emails) · تم التحميل${res.server === "failed" ? ". The server copy could not be updated right now." : ""}`,
  );
  loadStats();
});

$("reset").addEventListener("click", async () => {
  if (!confirm("Erase your personal scam filter? This cannot be undone. · هل تريد مسح الفلتر الشخصي؟")) return;
  const res = await call({ type: "modelReset" }, "model-msg");
  if (!res) return;
  showMsg(
    "model-msg",
    res.server === "failed"
      ? "Erased in this browser. The server copy could not be reached; try again later · تم المسح محلياً"
      : "Your filter was erased · تم المسح",
    res.server !== "failed",
  );
  loadStats();
});

loadSettings();
loadStats();
