const CACHE_VERSION = 'pwa-cache-v4'; // Bumped for production enhancements

self.addEventListener('install', (event) => {
  console.log('📦 Service Worker Installed');
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => {
      return cache.addAll([
        './index.html', './main.js', './manifest.json', './offline.html' // Added offline fallback
      ]).catch(err => console.error('Cache add failed:', err));
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keyList) =>
      Promise.all(
        keyList.filter((key) => key !== CACHE_VERSION)
          .map((key) => caches.delete(key))
      )
    ).catch(err => console.error('Cache cleanup failed:', err))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          const respClone = response.clone();
          caches.open(CACHE_VERSION).then(cache => cache.put(event.request, respClone));
          return response;
        })
        .catch(() => caches.match(event.request) || new Response('API offline', { status: 503 }))
    );
  } else {
    event.respondWith(
      caches.match(event.request).then((response) => {
        return response || fetch(event.request).catch(() => {
          if (event.request.mode === 'navigate') {
            return caches.match('./offline.html');
          }
          return new Response('Offline', { status: 503 });
        });
      }).catch(err => {
        console.error('Fetch error:', err);
        return new Response('Service error', { status: 500 });
      })
    );
  }
});
