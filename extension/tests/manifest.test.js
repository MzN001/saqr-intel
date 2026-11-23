// manifest.json sanity: valid JSON, every referenced file exists, shared libs load before the
// content scripts that use them, and the webmail hosts are covered.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { EXT } = require("./helpers.js");

const manifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));
const LIBS = ["lib/email_features.js", "lib/user_model.js", "lib/campaign_match.js"];

test("manifest basics", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
  assert.equal(manifest.background.service_worker, "background.js");
  assert.equal(manifest.options_ui.page, "options.html");
  for (const p of ["storage", "tabs", "scripting"]) assert.ok(manifest.permissions.includes(p), p);
});

test("every file the manifest names exists", () => {
  const files = new Set([manifest.background.service_worker, manifest.action.default_popup, manifest.options_ui.page]);
  for (const icon of Object.values(manifest.icons)) files.add(icon);
  for (const cs of manifest.content_scripts) for (const f of [...(cs.js || []), ...(cs.css || [])]) files.add(f);
  for (const w of manifest.web_accessible_resources) for (const f of w.resources) files.add(f);
  const missing = [...files].filter((f) => !fs.existsSync(path.join(EXT, f)));
  assert.deepEqual(missing, []);
});

test("Gmail / Outlook content scripts: libs, then common.js, then the provider file", () => {
  const byProvider = { "content/gmail.js": "https://mail.google.com/*", "content/outlook.js": "https://outlook.office.com/*" };
  for (const [file, match] of Object.entries(byProvider)) {
    const cs = manifest.content_scripts.find((c) => c.js.includes(file));
    assert.ok(cs, file);
    assert.ok(cs.matches.includes(match));
    assert.deepEqual(cs.js, [...LIBS, "content/common.js", file]);
    assert.equal(cs.run_at, "document_idle");
  }
  const outlook = manifest.content_scripts.find((c) => c.js.includes("content/outlook.js"));
  for (const h of ["outlook.live.com", "outlook.office.com", "outlook.office365.com", "outlook.cloud.microsoft"]) {
    assert.ok(outlook.matches.includes("https://" + h + "/*"), h);
  }
  const wip = manifest.content_scripts.find((c) => c.js.includes("content/wip.js"));
  for (const m of ["https://mail.yahoo.com/*", "https://mail.proton.me/*", "https://www.icloud.com/mail*", "https://mail.aol.com/*", "https://mail.zoho.com/*"]) {
    assert.ok(wip.matches.includes(m), m);
  }
});

test("background importScripts the same libs in the same order", () => {
  const src = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
  const m = src.match(/importScripts\(([^)]*)\)/);
  assert.ok(m);
  assert.deepEqual(JSON.parse("[" + m[1] + "]"), LIBS);
});
