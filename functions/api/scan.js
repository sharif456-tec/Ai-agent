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

function headerObject(headers) {
  const result = {};
  for (const [key, value] of headers.entries()) result[key] = value;
  return result;
}

function checkCookieAttributes(setCookie) {
  if (!setCookie) return [];
  const findings = [];
  const cookies = setCookie.split(/,(?=\s*[^;,=]+\s*=)/);
  cookies.forEach((cookie, index) => {
    const lower = cookie.toLowerCase();
    const name = (cookie.match(/^\s*([^=;\s]+)\s*=/) || [])[1] || `Cookie ${index + 1}`;
    if (!/\bsecure\b/i.test(cookie)) findings.push({ severity:'medium', title:`${name}: Secure attribute missing`, type:'cookie', evidence:cookie.slice(0,240), recommendation:'Add the Secure attribute so the cookie is sent only over HTTPS.' });
    if (!/\bhttponly\b/i.test(cookie)) findings.push({ severity:'medium', title:`${name}: HttpOnly attribute missing`, type:'cookie', evidence:cookie.slice(0,240), recommendation:'Add HttpOnly when client-side JavaScript does not need to read the cookie.' });
    if (!/\bsamesite\s*=/i.test(lower)) findings.push({ severity:'low', title:`${name}: SameSite attribute missing`, type:'cookie', evidence:cookie.slice(0,240), recommendation:'Set an appropriate SameSite value such as Lax or Strict.' });
  });
  return findings;
}

export async function onRequestPost(context) {
  let body;
  try { body = await context.request.json(); } catch { return json({ detail:'Invalid JSON body' },400); }
  const target = safeTarget(body?.target);
  if (!target) return json({ detail:'Only public http/https website URLs are allowed' },400);

  try {
    const started = Date.now();
    const response = await fetch(target.toString(), {
      method:'GET',
      headers:{'User-Agent':'AI-Security-Auditor/1.1'},
      redirect:'manual'
    });
    const location = response.headers.get('Location');
    const finalUrl = location ? new URL(location, target) : target;
    if (!safeTarget(finalUrl.toString())) return json({ detail:'Unsafe redirect blocked' },400);

    const findings = [];
    const checks = [
      ['Content-Security-Policy','medium','Helps restrict script and resource sources.','Add a restrictive Content-Security-Policy appropriate for the application.'],
      ['Strict-Transport-Security','medium','Instructs browsers to prefer HTTPS.','Add HSTS after confirming the site works correctly over HTTPS.'],
      ['X-Frame-Options','low','Reduces clickjacking exposure in supporting browsers.','Set DENY or SAMEORIGIN where framing is not required.'],
      ['X-Content-Type-Options','low','Prevents MIME-type sniffing.','Set X-Content-Type-Options: nosniff.'],
      ['Referrer-Policy','low','Controls how much referrer information is sent.','Set a deliberate policy such as strict-origin-when-cross-origin.'],
      ['Permissions-Policy','low','Limits browser features exposed to the page.','Define a restrictive Permissions-Policy for unused browser features.']
    ];
    for (const [name,severity,why,recommendation] of checks) {
      const present = response.headers.has(name);
      if (!present) findings.push({severity,title:`Missing ${name}`,type:'security-header',evidence:`Response header "${name}" was not present.`,why,recommendation});
    }
    if (finalUrl.protocol !== 'https:') findings.push({severity:'high',title:'Target is not using HTTPS',type:'transport',evidence:`Final URL uses ${finalUrl.protocol}`,why:'Unencrypted HTTP can expose traffic to interception or modification.',recommendation:'Serve the site over HTTPS and redirect HTTP to HTTPS.'});

    findings.push(...checkCookieAttributes(response.headers.get('Set-Cookie') || ''));

    const server = response.headers.get('Server');
    const powered = response.headers.get('X-Powered-By');
    const technologies = [];
    if (server) technologies.push(`Server: ${server}`);
    if (powered) technologies.push(`X-Powered-By: ${powered}`);
    if (server) findings.push({severity:'low',title:'Server technology disclosed',type:'information-disclosure',evidence:`Server: ${server}`,why:'Detailed server banners can reveal implementation information useful to attackers.',recommendation:'Minimize unnecessary server/version disclosure where practical.'});
    if (powered) findings.push({severity:'low',title:'X-Powered-By disclosed',type:'information-disclosure',evidence:`X-Powered-By: ${powered}`,why:'Framework/runtime disclosure provides unnecessary implementation detail.',recommendation:'Remove X-Powered-By if the application does not require it.'});

    const headerMap = headerObject(response.headers);
    const passedChecks = checks.filter(([name]) => response.headers.has(name)).map(([name,,why]) => ({check:name,status:'PASS',evidence:headerMap[name.toLowerCase()] || headerMap[name],why}));
    const failedChecks = findings.map(f => ({check:f.title,status:'FAIL',severity:f.severity,evidence:f.evidence,why:f.why,recommendation:f.recommendation}));
    const counts = Object.fromEntries(['critical','high','medium','low'].map(s => [s,findings.filter(f => f.severity === s).length]));
    const score = Math.max(0,100-counts.critical*30-counts.high*15-counts.medium*7-counts.low*3);

    return json({
      target:target.toString(), final_url:finalUrl.toString(), http_status:response.status,
      security_score:score, ...counts, findings, technologies,
      security_headers:headerMap, passed_checks:passedChecks, failed_checks:failedChecks,
      response_summary:{status_text:response.statusText,content_type:response.headers.get('Content-Type'),content_length:response.headers.get('Content-Length'),server, powered_by:powered, set_cookie_present:Boolean(response.headers.get('Set-Cookie')),redirect:location || null},
      scan_duration_ms:Date.now()-started,
      scanned_at:new Date().toISOString(), mode:'passive-safe-detailed-audit-cloudflare'
    });
  } catch(error) {
    return json({detail:`Target could not be checked: ${error.message}`},400);
  }
}
