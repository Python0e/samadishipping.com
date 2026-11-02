const CACHE_NAME = "samadi-shipping-shell-v1";
const APP_SHELL = [
    "/admin-login.html",
    "/manifest.webmanifest",
    "/favicon.svg"
];

self.addEventListener("install", (event) => {
    event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)));
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    event.waitUntil(caches.keys().then((keys) => Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
    )));
    self.clients.claim();
});

self.addEventListener("fetch", (event) => {
    const requestUrl = new URL(event.request.url);
    if (requestUrl.origin !== self.location.origin || requestUrl.pathname.startsWith("/api/")) {
        return;
    }

    if (event.request.mode === "navigate") {
        event.respondWith(fetch(event.request).catch(() => caches.match("/admin-login.html")));
        return;
    }

    event.respondWith(caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) return cachedResponse;
        return fetch(event.request);
    }));
});
