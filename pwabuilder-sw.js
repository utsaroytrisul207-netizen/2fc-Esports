
// 2FC E-SPORTS - Firebase Push Notification Service Worker

importScripts('https://www.gstatic.com/firebasejs/10.8.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.8.0/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyDsV0BWcuOo82m5lWdDae7tu_RgIxCL6GQ",
  authDomain: "fc-esports-fe1c4.firebaseapp.com",
  projectId: "fc-esports-fe1c4",
  storageBucket: "fc-esports-fe1c4.firebasestorage.app",
  messagingSenderId: "770892208283",
  appId: "1:770892208283:web:a0c8757985822396cf8e3e"
});

const messaging = firebase.messaging();

// BACKGROUND PUSH NOTIFICATION
messaging.onBackgroundMessage((payload) => {
  const data = payload?.data || {};

  return self.registration.showNotification(
    data.title || "2FC E-SPORTS",
    {
      body: data.body || "You have a new notification.",
      data: {
        url: data.url || data.targetUrl || "/"
      },
      tag: "2fc-" + (data.notificationId || Date.now()),
      renotify: true
    }
  );
});

// NOTIFICATION CLICK
self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  const target = new URL(
    event.notification.data?.url || "/",
    self.location.origin
  ).href;

  event.waitUntil((async () => {
    const windows = await clients.matchAll({
      type: "window",
      includeUncontrolled: true
    });

    for (const client of windows) {
      if ("focus" in client) {
        await client.focus();

        if ("navigate" in client) {
          await client.navigate(target);
        }

        return;
      }
    }

    if (clients.openWindow) {
      await clients.openWindow(target);
    }
  })());
});

// WORKBOX
importScripts('https://storage.googleapis.com/workbox-cdn/releases/5.1.2/workbox-sw.js');

const CACHE = "pwabuilder-page";
const offlineFallbackPage = "/";

// SKIP WAITING
self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }
});

// INSTALL
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => {
      return cache.add(offlineFallbackPage);
    })
  );
});

// ACTIVATE
self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    await clients.claim();
  })());
});

// NAVIGATION PRELOAD
if (workbox.navigationPreload.isSupported()) {
  workbox.navigationPreload.enable();
}

// OFFLINE NAVIGATION
self.addEventListener("fetch", (event) => {
  if (event.request.mode === "navigate") {
    event.respondWith((async () => {
      try {
        const preloadResp = await event.preloadResponse;

        if (preloadResp) {
          return preloadResp;
        }

        return await fetch(event.request);

      } catch (error) {
        const cache = await caches.open(CACHE);
        return await cache.match(offlineFallbackPage);
      }
    })());
  }
});
