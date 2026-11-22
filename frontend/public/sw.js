// SAQR Verify service worker: makes the citizen shield installable as a PWA (needed for the
// Android share target). It never caches scan results — every verdict is fetched live.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET" || event.request.mode !== "navigate") return;
  event.respondWith(fetch(event.request));
});
