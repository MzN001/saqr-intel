// SAQR-INTEL extension — the public addresses every part of the extension shares (no build step).
// Loaded by the service worker (importScripts), popup.html, and the "work in progress" content script
// (manifest.json), and require()d by the node tests. Change an address here only.

(function (root) {
  "use strict";
  const config = Object.freeze({
    DEFAULT_API: "https://saqr-intel-api.onrender.com", // SAQR-INTEL backend (Render)
    APP_ORIGIN: "https://saqr-intel.vercel.app", // citizen web app (Vercel)
    APP_URL: "https://saqr-intel.vercel.app/citizen", // its main page (paste an email there)
  });
  if (typeof module === "object" && module.exports) module.exports = config;
  root.SaqrConfig = config;
})(typeof globalThis !== "undefined" ? globalThis : this);
