const CACHE_VERSION = 'pwa-cache-v2';

const STATIC_ASSETS = [
    './',
    './index.html',
    './main.js',
    './manifest.json',
    './sw.js',
    // Add all icons and referenced images (example):
    './favicon.ico',
    // './logo192.png',
    // './logo512.png',
    // ...any other files used in your HTML/CSS
];

self.addEventListener('install', (event) => {
    console.log('📦 Service Worker Installed');
    event.waitUntil(
        caches.open(CACHE_VERSION).then((cache) => {
            return cache.addAll(STATIC_ASSETS);
        }).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keyList) =>
            Promise.all(
                keyList
                    .filter((key) => key !== CACHE_VERSION)
                    .map((key) => caches.delete(key))
            )
        ).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    // For navigation (i.e., opening app or SPA route), always respond with index.html
    if (event.request.mode === 'navigate') {
        event.respondWith(
            caches.match('./index.html')
                .then(response => response || fetch(event.request))
        );
        return;
    }
    // Otherwise, try cache, then network
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request).catch(() => {
                if (event.request.destination === 'document') {
                    return caches.match('./index.html');
                }
            });
        })
    );
});
