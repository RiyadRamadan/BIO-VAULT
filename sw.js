const CACHE_VERSION = 'pwa-cache-v3';

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then(cache =>
      cache.addAll([
        './index.html',
        './main.js',
        './manifest.json',
        './icon-192.png',
        './icon-512.png'
      ])
    )
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(key => key !== CACHE_VERSION)
            .map(key => caches.delete(key))
      )
    )
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(response =>
      response ||
      fetch(event.request).catch(() =>
        event.request.destination === 'document'
          ? caches.match('./index.html')
          : undefined
      )
    )
  );
});
