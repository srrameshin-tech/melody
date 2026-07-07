const CACHE_NAME = 'melody-shell-v1';
const SHELL_FILES = ['/', '/index.html', '/manifest.json'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)).catch(()=>{})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Network-first for HTML shell, let media requests (R2 worker) pass straight through
self.addEventListener('fetch', (event) => {
  const url = event.request.url;
  if (url.includes('workers.dev') || url.includes('firebasedatabase.app') || url.includes('gstatic.com')) {
    return; // don't intercept API/media/firebase calls
  }
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
