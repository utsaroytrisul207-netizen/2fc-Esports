
/* =========================================
   2FC E-SPORTS SERVICE WORKER
   Firebase Background Push + Offline Support
========================================= */

// Firebase SDK
importScripts(
  'https://www.gstatic.com/firebasejs/10.8.0/firebase-app-compat.js'
);

importScripts(
  'https://www.gstatic.com/firebasejs/10.8.0/firebase-messaging-compat.js'
);

// =========================================
// FIREBASE CONFIGURATION
// =========================================
firebase.initializeApp({
  apiKey: "AIzaSyDsV0BWcuOo82m5lWdDae7tu_RgIxCL6GQ",
  authDomain: "fc-esports-fe1c4.firebaseapp.com",
  projectId: "fc-esports-fe1c4",
  storageBucket: "fc-esports-fe1c4.firebasestorage.app",
  messagingSenderId: "770892208283",
  appId: "1:770892208283:web:a0c8757985822396cf8e3e"
});

const messaging = firebase.messaging();

// =========================================
// BACKGROUND PUSH NOTIFICATION
// =========================================
messaging.onBackgroundMessage((payload) => {

  console.log('[2FC PUSH] Background message received:', payload);

  const data = payload.data || {};
  const notification = payload.notification || {};

  const title =
    data.title ||
    notification.title ||
    "2FC E-SPORTS";

  const body =
    data.body ||
    notification.body ||
    "You have a new notification.";

  const notificationId =
    data.notificationId ||
    Date.now().toString();

  const targetUrl =
    data.url ||
    data.targetUrl ||
    "/";

  console.log('[2FC PUSH] Showing notification:', {
    title,
    notificationId,
    targetUrl
  });

  // IMPORTANT: Return the Promise so the notification
  // operation can finish before the background event ends.
  return self.registration.showNotification(title, {
    body: body,

    icon: "/favicon.ico",
    badge: "/favicon.ico",

    tag: "2fc-" + notificationId,

    renotify: true,

    data: {
      url: targetUrl,
      notificationId: notificationId
    }
  });
});

// =========================================
// NOTIFICATION CLICK
// =========================================
self.addEventListener("notificationclick", (event) => {

  console.log('[2FC PUSH] Notification clicked');

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

// =========================================
// WORKBOX OFFLINE SUPPORT
// =========================================
importScripts(
  'https://storage.googleapis.com/workbox-cdn/releases/5.1.2/workbox-sw.js'
);

const CACHE = "pwabuilder-page";
const offlineFallbackPage = "/";

// =========================================
// SKIP WAITING MESSAGE
// =========================================
self.addEventListener("message", (event) => {

  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }

});

// =========================================
// INSTALL
// =========================================
self.addEventListener("install", (event) => {

  event.waitUntil(
    caches.open(CACHE)
      .then((cache) => cache.add(offlineFallbackPage))
  );

});

// =========================================
// ACTIVATE
// =========================================
self.addEventListener("activate", (event) => {

  event.waitUntil(
    clients.claim()
  );

});

// =========================================
// NAVIGATION PRELOAD
// =========================================
if (
  self.workbox &&
  workbox.navigationPreload &&
  workbox.navigationPreload.isSupported()
) {
  workbox.navigationPreload.enable();
}

// =========================================
// OFFLINE FETCH SUPPORT
// =========================================
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

        console.error('[2FC OFFLINE] Network error:', error);

        const cache = await caches.open(CACHE);

        return await cache.match(offlineFallbackPage);
      }

    })());

  }

});

console.log('[2FC] Service Worker loaded successfully');
