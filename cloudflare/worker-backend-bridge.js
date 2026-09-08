// Cloudflare Worker -> AI Backend Bridge

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const backend = env.BACKEND_URL;
    if (!backend) {
      return new Response(JSON.stringify({error: "BACKEND_URL not configured"}), {
        status: 500,
        headers: {"content-type": "application/json"}
      });
    }

    const target = backend + url.pathname + url.search;

    const response = await fetch(target, {
      method: request.method,
      headers: request.headers,
      body: request.method === "GET" ? undefined : request.body
    });

    return new Response(response.body, {
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") || "application/json",
        "access-control-allow-origin": "*"
      }
    });
  }
};
