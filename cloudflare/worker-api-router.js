const ALLOWED_ORIGIN = "https://agentusa.pages.dev";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const cors = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    const backend = env.BACKEND_URL;

    if (!backend) {
      return Response.json(
        { error: "BACKEND_URL is not configured" },
        { status: 500, headers: cors }
      );
    }

    let endpoint = "/api/health";

    if (url.pathname.startsWith("/api/scan")) endpoint = "/api/scan";
    if (url.pathname.startsWith("/api/logs")) endpoint = "/api/logs";
    if (url.pathname.startsWith("/api/status")) endpoint = "/api/status";

    const response = await fetch(backend + endpoint, {
      method: request.method,
      headers: { "Content-Type": "application/json" },
      body: request.method === "GET" ? undefined : await request.text()
    });

    return new Response(await response.text(), {
      status: response.status,
      headers: {
        ...cors,
        "Content-Type": "application/json"
      }
    });
  }
};
