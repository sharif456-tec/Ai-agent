function json(data, status = 200) {
  return Response.json(data, { status });
}

function safeTarget(value) {
  try {
    const u = new URL(value);
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    if (u.username || u.password) return null;
    const h = u.hostname.toLowerCase();
    if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return null;
    if (/^(127\.|10\.|192\.168\.|169\.254\.)/.test(h)) return null;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(h)) return null;
    if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:')) return null;
    return u;
  } catch { return null; }
}

export async function onRequestPost(context) {
  let body;
  try { body = await context.request.json(); } catch { return json({ detail: 'Invalid JSON body' }, 400); }
  const target = safeTarget(body?.target);
  if (!target) return json({ detail: 'Only public http/https website URLs are allowed' }, 400);

  try {
    const response = await fetch(target.toString(), {
      method: 'GET',
      headers: { 'User-Agent': 'AI-Security-Auditor/1.0' },
      redirect: 'manual'
    });
    const location = response.headers.get('Location');
    const finalUrl = location ? new URL(location, target) : target;
    if (!safeTarget(finalUrl.toString())) return json({ detail: 'Unsafe redirect blocked' }, 400);

    const findings = [];
    const headersToCheck = {
      'Content-Security-Policy': 'medium',
      'Strict-Transport-Security': 'medium',
      'X-Frame-Options': 'low',
      'X-Content-Type-Options': 'low',
      'Referrer-Policy': 'low',
      'Permissions-Policy': 'low'
    };
    for (const [name, severity] of Object.entries(headersToCheck)) {
      if (!response.headers.has(name)) findings.push({ severity, title: `Missing ${name}`, type: 'security-header' });
    }
    if (finalUrl.protocol !== 'https:') findings.push({ severity: 'high', title: 'Target is not using HTTPS', type: 'transport' });

    const cookie = response.headers.get('Set-Cookie') || '';
    if (cookie && !/\bSecure\b/i.test(cookie)) findings.push({ severity: 'medium', title: 'Cookie may be missing Secure attribute', type: 'cookie' });
    if (cookie && !/\bHttpOnly\b/i.test(cookie)) findings.push({ severity: 'medium', title: 'Cookie may be missing HttpOnly attribute', type: 'cookie' });

    const technologies = [];
    const server = response.headers.get('Server');
    const powered = response.headers.get('X-Powered-By');
    if (server) technologies.push(`Server: ${server}`);
    if (powered) technologies.push(`X-Powered-By: ${powered}`);

    const counts = Object.fromEntries(['critical','high','medium','low'].map(s => [s, findings.filter(f => f.severity === s).length]));
    const score = Math.max(0, 100 - counts.critical * 30 - counts.high * 15 - counts.medium * 7 - counts.low * 3);
    return json({ target: target.toString(), final_url: finalUrl.toString(), http_status: response.status, security_score: score, ...counts, findings, technologies, scanned_at: new Date().toISOString(), mode: 'passive-safe-audit-cloudflare' });
  } catch (error) {
    return json({ detail: `Target could not be checked: ${error.message}` }, 400);
  }
}
