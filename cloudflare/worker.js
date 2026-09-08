export default {
  async fetch(request) {
    return new Response(JSON.stringify({
      status: 'Cloudflare API Gateway online'
    }), {
      headers: { 'content-type': 'application/json' }
    });
  }
};
