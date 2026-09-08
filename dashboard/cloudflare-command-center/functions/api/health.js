export function onRequestGet() {
  return Response.json({ agent: 'online', time: new Date().toISOString(), platform: 'cloudflare-pages-functions' });
}
