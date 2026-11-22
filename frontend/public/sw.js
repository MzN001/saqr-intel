// SAQR Verify service worker: installable PWA (Android share target, iPhone Home Screen app) and
// SAQR scam-alert push notifications. It never caches scan results — every verdict is fetched live.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET" || event.request.mode !== "navigate") return;
  event.respondWith(fetch(event.request));
});

// A SAQR alert: "🛑 SAQR blocked a scam website …". Payload is JSON from the backend.
self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { body: event.data ? event.data.text() : "" };
  }
  const title = data.title || "🛑 SAQR blocked a scam website";
  event.waitUntil(
    self.registration.showNotification(title, {
      body: data.body || "A fraudulent website was blocked on your phone. Tap for details.",
      icon: "/icons/icon-192.png",
      badge: "/icons/icon-192.png",
      tag: data.tag || "saqr-alert",
      renotify: true,
      requireInteraction: true,
      lang: data.lang || "en",
      dir: data.lang === "ar" ? "rtl" : "ltr",
      timestamp: data.ts || Date.now(),
      data: { url: data.url || "/citizen" },
    }),
  );
});

// Tapping the alert opens (or focuses) SAQR on the red police warning for that site.
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = new URL(event.notification.data?.url || "/citizen", self.location.origin).href;
  event.waitUntil(
    (async () => {
      const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const w of wins) {
        if (new URL(w.url).origin === self.location.origin && "navigate" in w) {
          await w.focus();
          return w.navigate(target);
        }
      }
      return self.clients.openWindow(target);
    })(),
  );
});
