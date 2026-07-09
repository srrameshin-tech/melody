// This service worker is deprecated. Melody now manages offline downloads
// directly via the Cache Storage API from index.html (cache name:
// 'melody-offline-media'). This file is kept only so that any browser
// still controlled by an old version of this service worker can safely
// retire it — WITHOUT touching any Cache Storage buckets, so downloaded
// offline songs/videos are never deleted.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => {
  event.waitUntil(
    self.registration.unregister().then(() => self.clients.matchAll())
      .then((clients) => { clients.forEach((client) => client.navigate(client.url)); })
  );
});
