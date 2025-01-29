self.addEventListener('install', (event) => {
    console.log('📦 Service Worker Installed');
    event.waitUntil(
        caches.open('pwa-cache').then((cache) => {
            return cache.addAll([
                './index.html',
                './main.js',
                './manifest.json',
                // Add other assets like CSS or images if any
            ]);
        })
    );
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    );
});
